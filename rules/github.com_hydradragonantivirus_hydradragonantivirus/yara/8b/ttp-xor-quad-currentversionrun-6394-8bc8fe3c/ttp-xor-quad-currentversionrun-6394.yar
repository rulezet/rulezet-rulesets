rule TTP_XOR_QUAD_CurrentVersionRun_6394 {
  strings:
    $key_6394 = { 30 fb [2] 14 f5 [2] 3f d9 [2] 11 fb [2] 05 e0 [2] 0a fa [2] 14 e7 [2] 16 e6 [2] 0d e0 [2] 11 e7 [2] 0d c8 }

  condition:
    any of them
}