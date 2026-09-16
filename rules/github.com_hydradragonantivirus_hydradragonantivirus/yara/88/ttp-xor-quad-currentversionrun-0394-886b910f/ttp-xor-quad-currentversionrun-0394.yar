rule TTP_XOR_QUAD_CurrentVersionRun_0394 {
  strings:
    $key_0394 = { 50 fb [2] 74 f5 [2] 5f d9 [2] 71 fb [2] 65 e0 [2] 6a fa [2] 74 e7 [2] 76 e6 [2] 6d e0 [2] 71 e7 [2] 6d c8 }

  condition:
    any of them
}