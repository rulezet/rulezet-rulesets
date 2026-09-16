rule TTP_XOR_QUAD_CurrentVersionRun_9594 {
  strings:
    $key_9594 = { c6 fb [2] e2 f5 [2] c9 d9 [2] e7 fb [2] f3 e0 [2] fc fa [2] e2 e7 [2] e0 e6 [2] fb e0 [2] e7 e7 [2] fb c8 }

  condition:
    any of them
}