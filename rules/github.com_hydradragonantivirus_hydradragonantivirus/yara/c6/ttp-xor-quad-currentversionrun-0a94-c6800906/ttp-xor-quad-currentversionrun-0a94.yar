rule TTP_XOR_QUAD_CurrentVersionRun_0a94 {
  strings:
    $key_0a94 = { 59 fb [2] 7d f5 [2] 56 d9 [2] 78 fb [2] 6c e0 [2] 63 fa [2] 7d e7 [2] 7f e6 [2] 64 e0 [2] 78 e7 [2] 64 c8 }

  condition:
    any of them
}