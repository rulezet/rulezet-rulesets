rule TTP_XOR_QUAD_CurrentVersionRun_1a94 {
  strings:
    $key_1a94 = { 49 fb [2] 6d f5 [2] 46 d9 [2] 68 fb [2] 7c e0 [2] 73 fa [2] 6d e7 [2] 6f e6 [2] 74 e0 [2] 68 e7 [2] 74 c8 }

  condition:
    any of them
}