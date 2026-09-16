rule TTP_XOR_QUAD_CurrentVersionRun_b294 {
  strings:
    $key_b294 = { e1 fb [2] c5 f5 [2] ee d9 [2] c0 fb [2] d4 e0 [2] db fa [2] c5 e7 [2] c7 e6 [2] dc e0 [2] c0 e7 [2] dc c8 }

  condition:
    any of them
}