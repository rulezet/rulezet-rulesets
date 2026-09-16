rule TTP_XOR_QUAD_CurrentVersionRun_eb94 {
  strings:
    $key_eb94 = { b8 fb [2] 9c f5 [2] b7 d9 [2] 99 fb [2] 8d e0 [2] 82 fa [2] 9c e7 [2] 9e e6 [2] 85 e0 [2] 99 e7 [2] 85 c8 }

  condition:
    any of them
}