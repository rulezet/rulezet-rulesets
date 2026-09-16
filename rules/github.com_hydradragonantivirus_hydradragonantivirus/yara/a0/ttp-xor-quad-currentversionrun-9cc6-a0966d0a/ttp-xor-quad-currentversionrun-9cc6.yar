rule TTP_XOR_QUAD_CurrentVersionRun_9cc6 {
  strings:
    $key_9cc6 = { cf a9 [2] eb a7 [2] c0 8b [2] ee a9 [2] fa b2 [2] f5 a8 [2] eb b5 [2] e9 b4 [2] f2 b2 [2] ee b5 [2] f2 9a }

  condition:
    any of them
}