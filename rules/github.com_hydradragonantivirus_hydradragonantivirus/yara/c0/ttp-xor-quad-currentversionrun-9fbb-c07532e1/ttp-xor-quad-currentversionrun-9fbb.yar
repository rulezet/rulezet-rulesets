rule TTP_XOR_QUAD_CurrentVersionRun_9fbb {
  strings:
    $key_9fbb = { cc d4 [2] e8 da [2] c3 f6 [2] ed d4 [2] f9 cf [2] f6 d5 [2] e8 c8 [2] ea c9 [2] f1 cf [2] ed c8 [2] f1 e7 }

  condition:
    any of them
}