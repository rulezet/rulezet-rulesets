rule TTP_XOR_QUAD_CurrentVersionRun_9ccc {
  strings:
    $key_9ccc = { cf a3 [2] eb ad [2] c0 81 [2] ee a3 [2] fa b8 [2] f5 a2 [2] eb bf [2] e9 be [2] f2 b8 [2] ee bf [2] f2 90 }

  condition:
    any of them
}