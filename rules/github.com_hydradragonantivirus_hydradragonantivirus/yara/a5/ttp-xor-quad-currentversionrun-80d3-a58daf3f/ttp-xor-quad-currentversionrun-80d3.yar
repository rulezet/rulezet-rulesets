rule TTP_XOR_QUAD_CurrentVersionRun_80d3 {
  strings:
    $key_80d3 = { d3 bc [2] f7 b2 [2] dc 9e [2] f2 bc [2] e6 a7 [2] e9 bd [2] f7 a0 [2] f5 a1 [2] ee a7 [2] f2 a0 [2] ee 8f }

  condition:
    any of them
}