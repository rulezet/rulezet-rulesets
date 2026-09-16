rule TTP_XOR_QUAD_CurrentVersionRun_7979 {
  strings:
    $key_7979 = { 2a 16 [2] 0e 18 [2] 25 34 [2] 0b 16 [2] 1f 0d [2] 10 17 [2] 0e 0a [2] 0c 0b [2] 17 0d [2] 0b 0a [2] 17 25 }

  condition:
    any of them
}