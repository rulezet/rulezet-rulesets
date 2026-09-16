rule TTP_XOR_QUAD_CurrentVersionRun_9fb7 {
  strings:
    $key_9fb7 = { cc d8 [2] e8 d6 [2] c3 fa [2] ed d8 [2] f9 c3 [2] f6 d9 [2] e8 c4 [2] ea c5 [2] f1 c3 [2] ed c4 [2] f1 eb }

  condition:
    any of them
}