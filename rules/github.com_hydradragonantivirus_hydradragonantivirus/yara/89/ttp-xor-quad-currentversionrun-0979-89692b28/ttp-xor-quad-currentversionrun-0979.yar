rule TTP_XOR_QUAD_CurrentVersionRun_0979 {
  strings:
    $key_0979 = { 5a 16 [2] 7e 18 [2] 55 34 [2] 7b 16 [2] 6f 0d [2] 60 17 [2] 7e 0a [2] 7c 0b [2] 67 0d [2] 7b 0a [2] 67 25 }

  condition:
    any of them
}