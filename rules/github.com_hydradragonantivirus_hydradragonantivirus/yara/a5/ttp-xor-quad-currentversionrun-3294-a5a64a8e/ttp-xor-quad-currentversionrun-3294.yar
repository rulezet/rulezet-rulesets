rule TTP_XOR_QUAD_CurrentVersionRun_3294 {
  strings:
    $key_3294 = { 61 fb [2] 45 f5 [2] 6e d9 [2] 40 fb [2] 54 e0 [2] 5b fa [2] 45 e7 [2] 47 e6 [2] 5c e0 [2] 40 e7 [2] 5c c8 }

  condition:
    any of them
}