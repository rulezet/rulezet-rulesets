rule TTP_XOR_QUAD_CurrentVersionRun_9cc8 {
  strings:
    $key_9cc8 = { cf a7 [2] eb a9 [2] c0 85 [2] ee a7 [2] fa bc [2] f5 a6 [2] eb bb [2] e9 ba [2] f2 bc [2] ee bb [2] f2 94 }

  condition:
    any of them
}