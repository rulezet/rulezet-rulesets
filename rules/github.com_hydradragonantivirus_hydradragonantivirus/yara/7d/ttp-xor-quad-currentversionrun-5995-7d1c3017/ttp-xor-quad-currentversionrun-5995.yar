rule TTP_XOR_QUAD_CurrentVersionRun_5995 {
  strings:
    $key_5995 = { 0a fa [2] 2e f4 [2] 05 d8 [2] 2b fa [2] 3f e1 [2] 30 fb [2] 2e e6 [2] 2c e7 [2] 37 e1 [2] 2b e6 [2] 37 c9 }

  condition:
    any of them
}