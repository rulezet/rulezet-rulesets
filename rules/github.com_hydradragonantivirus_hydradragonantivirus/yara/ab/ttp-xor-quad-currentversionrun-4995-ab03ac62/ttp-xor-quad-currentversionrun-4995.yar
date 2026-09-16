rule TTP_XOR_QUAD_CurrentVersionRun_4995 {
  strings:
    $key_4995 = { 1a fa [2] 3e f4 [2] 15 d8 [2] 3b fa [2] 2f e1 [2] 20 fb [2] 3e e6 [2] 3c e7 [2] 27 e1 [2] 3b e6 [2] 27 c9 }

  condition:
    any of them
}