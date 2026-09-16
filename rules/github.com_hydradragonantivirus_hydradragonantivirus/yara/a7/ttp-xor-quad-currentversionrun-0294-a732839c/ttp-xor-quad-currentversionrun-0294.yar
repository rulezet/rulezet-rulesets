rule TTP_XOR_QUAD_CurrentVersionRun_0294 {
  strings:
    $key_0294 = { 51 fb [2] 75 f5 [2] 5e d9 [2] 70 fb [2] 64 e0 [2] 6b fa [2] 75 e7 [2] 77 e6 [2] 6c e0 [2] 70 e7 [2] 6c c8 }

  condition:
    any of them
}