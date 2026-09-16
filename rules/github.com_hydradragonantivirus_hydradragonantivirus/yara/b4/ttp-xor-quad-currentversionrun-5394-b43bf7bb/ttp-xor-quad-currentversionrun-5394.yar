rule TTP_XOR_QUAD_CurrentVersionRun_5394 {
  strings:
    $key_5394 = { 00 fb [2] 24 f5 [2] 0f d9 [2] 21 fb [2] 35 e0 [2] 3a fa [2] 24 e7 [2] 26 e6 [2] 3d e0 [2] 21 e7 [2] 3d c8 }

  condition:
    any of them
}