rule TTP_XOR_QUAD_CurrentVersionRun_ea94 {
  strings:
    $key_ea94 = { b9 fb [2] 9d f5 [2] b6 d9 [2] 98 fb [2] 8c e0 [2] 83 fa [2] 9d e7 [2] 9f e6 [2] 84 e0 [2] 98 e7 [2] 84 c8 }

  condition:
    any of them
}