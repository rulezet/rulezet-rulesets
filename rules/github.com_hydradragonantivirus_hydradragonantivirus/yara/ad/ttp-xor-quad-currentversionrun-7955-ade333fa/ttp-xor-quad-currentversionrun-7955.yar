rule TTP_XOR_QUAD_CurrentVersionRun_7955 {
  strings:
    $key_7955 = { 2a 3a [2] 0e 34 [2] 25 18 [2] 0b 3a [2] 1f 21 [2] 10 3b [2] 0e 26 [2] 0c 27 [2] 17 21 [2] 0b 26 [2] 17 09 }

  condition:
    any of them
}