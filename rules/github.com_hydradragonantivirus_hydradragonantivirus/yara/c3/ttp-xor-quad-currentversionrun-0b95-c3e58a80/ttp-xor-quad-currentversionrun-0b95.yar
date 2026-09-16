rule TTP_XOR_QUAD_CurrentVersionRun_0b95 {
  strings:
    $key_0b95 = { 58 fa [2] 7c f4 [2] 57 d8 [2] 79 fa [2] 6d e1 [2] 62 fb [2] 7c e6 [2] 7e e7 [2] 65 e1 [2] 79 e6 [2] 65 c9 }

  condition:
    any of them
}