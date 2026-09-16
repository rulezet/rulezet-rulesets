rule TTP_XOR_QUAD_CurrentVersionRun_0b94 {
  strings:
    $key_0b94 = { 58 fb [2] 7c f5 [2] 57 d9 [2] 79 fb [2] 6d e0 [2] 62 fa [2] 7c e7 [2] 7e e6 [2] 65 e0 [2] 79 e7 [2] 65 c8 }

  condition:
    any of them
}