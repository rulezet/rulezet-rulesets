rule TTP_XOR_QUAD_CurrentVersionRun_9f95 {
  strings:
    $key_9f95 = { cc fa [2] e8 f4 [2] c3 d8 [2] ed fa [2] f9 e1 [2] f6 fb [2] e8 e6 [2] ea e7 [2] f1 e1 [2] ed e6 [2] f1 c9 }

  condition:
    any of them
}