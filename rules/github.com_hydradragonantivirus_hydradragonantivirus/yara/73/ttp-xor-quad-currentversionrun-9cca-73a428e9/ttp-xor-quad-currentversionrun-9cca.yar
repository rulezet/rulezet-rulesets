rule TTP_XOR_QUAD_CurrentVersionRun_9cca {
  strings:
    $key_9cca = { cf a5 [2] eb ab [2] c0 87 [2] ee a5 [2] fa be [2] f5 a4 [2] eb b9 [2] e9 b8 [2] f2 be [2] ee b9 [2] f2 96 }

  condition:
    any of them
}