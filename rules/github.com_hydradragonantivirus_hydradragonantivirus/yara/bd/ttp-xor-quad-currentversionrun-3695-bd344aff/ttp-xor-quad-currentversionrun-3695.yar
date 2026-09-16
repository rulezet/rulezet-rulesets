rule TTP_XOR_QUAD_CurrentVersionRun_3695 {
  strings:
    $key_3695 = { 65 fa [2] 41 f4 [2] 6a d8 [2] 44 fa [2] 50 e1 [2] 5f fb [2] 41 e6 [2] 43 e7 [2] 58 e1 [2] 44 e6 [2] 58 c9 }

  condition:
    any of them
}