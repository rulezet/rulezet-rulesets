rule TTP_XOR_QUAD_CurrentVersionRun_9cd4 {
  strings:
    $key_9cd4 = { cf bb [2] eb b5 [2] c0 99 [2] ee bb [2] fa a0 [2] f5 ba [2] eb a7 [2] e9 a6 [2] f2 a0 [2] ee a7 [2] f2 88 }

  condition:
    any of them
}