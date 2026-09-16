rule TTP_XOR_QUAD_CurrentVersionRun_9cd5 {
  strings:
    $key_9cd5 = { cf ba [2] eb b4 [2] c0 98 [2] ee ba [2] fa a1 [2] f5 bb [2] eb a6 [2] e9 a7 [2] f2 a1 [2] ee a6 [2] f2 89 }

  condition:
    any of them
}