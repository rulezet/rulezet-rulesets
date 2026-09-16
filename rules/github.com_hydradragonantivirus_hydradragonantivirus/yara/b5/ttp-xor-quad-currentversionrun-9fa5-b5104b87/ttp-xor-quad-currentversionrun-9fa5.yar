rule TTP_XOR_QUAD_CurrentVersionRun_9fa5 {
  strings:
    $key_9fa5 = { cc ca [2] e8 c4 [2] c3 e8 [2] ed ca [2] f9 d1 [2] f6 cb [2] e8 d6 [2] ea d7 [2] f1 d1 [2] ed d6 [2] f1 f9 }

  condition:
    any of them
}