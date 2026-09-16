rule TTP_XOR_QUAD_CurrentVersionRun_3995 {
  strings:
    $key_3995 = { 6a fa [2] 4e f4 [2] 65 d8 [2] 4b fa [2] 5f e1 [2] 50 fb [2] 4e e6 [2] 4c e7 [2] 57 e1 [2] 4b e6 [2] 57 c9 }

  condition:
    any of them
}