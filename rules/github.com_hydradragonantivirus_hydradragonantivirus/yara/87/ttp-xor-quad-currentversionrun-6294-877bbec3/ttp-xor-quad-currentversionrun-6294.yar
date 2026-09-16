rule TTP_XOR_QUAD_CurrentVersionRun_6294 {
  strings:
    $key_6294 = { 31 fb [2] 15 f5 [2] 3e d9 [2] 10 fb [2] 04 e0 [2] 0b fa [2] 15 e7 [2] 17 e6 [2] 0c e0 [2] 10 e7 [2] 0c c8 }

  condition:
    any of them
}