rule TTP_XOR_QUAD_CurrentVersionRun_4a94 {
  strings:
    $key_4a94 = { 19 fb [2] 3d f5 [2] 16 d9 [2] 38 fb [2] 2c e0 [2] 23 fa [2] 3d e7 [2] 3f e6 [2] 24 e0 [2] 38 e7 [2] 24 c8 }

  condition:
    any of them
}