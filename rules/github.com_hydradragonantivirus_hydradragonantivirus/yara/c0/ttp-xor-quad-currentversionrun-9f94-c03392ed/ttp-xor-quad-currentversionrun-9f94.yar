rule TTP_XOR_QUAD_CurrentVersionRun_9f94 {
  strings:
    $key_9f94 = { cc fb [2] e8 f5 [2] c3 d9 [2] ed fb [2] f9 e0 [2] f6 fa [2] e8 e7 [2] ea e6 [2] f1 e0 [2] ed e7 [2] f1 c8 }

  condition:
    any of them
}