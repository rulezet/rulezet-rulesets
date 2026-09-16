rule TTP_XOR_QUAD_CurrentVersionRun_2a94 {
  strings:
    $key_2a94 = { 79 fb [2] 5d f5 [2] 76 d9 [2] 58 fb [2] 4c e0 [2] 43 fa [2] 5d e7 [2] 5f e6 [2] 44 e0 [2] 58 e7 [2] 44 c8 }

  condition:
    any of them
}