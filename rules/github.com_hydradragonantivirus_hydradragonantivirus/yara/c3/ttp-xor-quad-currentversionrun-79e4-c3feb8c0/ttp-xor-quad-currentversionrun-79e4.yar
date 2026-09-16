rule TTP_XOR_QUAD_CurrentVersionRun_79e4 {
  strings:
    $key_79e4 = { 2a 8b [2] 0e 85 [2] 25 a9 [2] 0b 8b [2] 1f 90 [2] 10 8a [2] 0e 97 [2] 0c 96 [2] 17 90 [2] 0b 97 [2] 17 b8 }

  condition:
    any of them
}