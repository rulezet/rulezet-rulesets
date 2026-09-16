rule TTP_XOR_QUAD_CurrentVersionRun_9fba {
  strings:
    $key_9fba = { cc d5 [2] e8 db [2] c3 f7 [2] ed d5 [2] f9 ce [2] f6 d4 [2] e8 c9 [2] ea c8 [2] f1 ce [2] ed c9 [2] f1 e6 }

  condition:
    any of them
}