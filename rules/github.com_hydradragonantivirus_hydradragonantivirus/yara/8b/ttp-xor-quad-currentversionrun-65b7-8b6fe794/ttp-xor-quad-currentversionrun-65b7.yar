rule TTP_XOR_QUAD_CurrentVersionRun_65b7 {
  strings:
    $key_65b7 = { 36 d8 [2] 12 d6 [2] 39 fa [2] 17 d8 [2] 03 c3 [2] 0c d9 [2] 12 c4 [2] 10 c5 [2] 0b c3 [2] 17 c4 [2] 0b eb }

  condition:
    any of them
}