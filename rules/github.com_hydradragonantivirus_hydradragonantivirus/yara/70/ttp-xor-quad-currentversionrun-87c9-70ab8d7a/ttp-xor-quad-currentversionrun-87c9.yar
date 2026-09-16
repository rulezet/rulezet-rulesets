rule TTP_XOR_QUAD_CurrentVersionRun_87c9 {
  strings:
    $key_87c9 = { d4 a6 [2] f0 a8 [2] db 84 [2] f5 a6 [2] e1 bd [2] ee a7 [2] f0 ba [2] f2 bb [2] e9 bd [2] f5 ba [2] e9 95 }

  condition:
    any of them
}