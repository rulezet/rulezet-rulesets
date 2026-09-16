rule TTP_XOR_QUAD_CurrentVersionRun_f595 {
  strings:
    $key_f595 = { a6 fa [2] 82 f4 [2] a9 d8 [2] 87 fa [2] 93 e1 [2] 9c fb [2] 82 e6 [2] 80 e7 [2] 9b e1 [2] 87 e6 [2] 9b c9 }

  condition:
    any of them
}