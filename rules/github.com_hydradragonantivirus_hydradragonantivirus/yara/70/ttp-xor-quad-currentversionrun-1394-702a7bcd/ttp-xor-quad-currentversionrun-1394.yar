rule TTP_XOR_QUAD_CurrentVersionRun_1394 {
  strings:
    $key_1394 = { 40 fb [2] 64 f5 [2] 4f d9 [2] 61 fb [2] 75 e0 [2] 7a fa [2] 64 e7 [2] 66 e6 [2] 7d e0 [2] 61 e7 [2] 7d c8 }

  condition:
    any of them
}