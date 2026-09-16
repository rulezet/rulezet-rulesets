rule TTP_XOR_QUAD_CurrentVersionRun_f5b7 {
  strings:
    $key_f5b7 = { a6 d8 [2] 82 d6 [2] a9 fa [2] 87 d8 [2] 93 c3 [2] 9c d9 [2] 82 c4 [2] 80 c5 [2] 9b c3 [2] 87 c4 [2] 9b eb }

  condition:
    any of them
}