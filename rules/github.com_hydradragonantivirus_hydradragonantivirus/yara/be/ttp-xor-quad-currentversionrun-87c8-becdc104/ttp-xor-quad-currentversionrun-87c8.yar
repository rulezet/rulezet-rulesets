rule TTP_XOR_QUAD_CurrentVersionRun_87c8 {
  strings:
    $key_87c8 = { d4 a7 [2] f0 a9 [2] db 85 [2] f5 a7 [2] e1 bc [2] ee a6 [2] f0 bb [2] f2 ba [2] e9 bc [2] f5 bb [2] e9 94 }

  condition:
    any of them
}