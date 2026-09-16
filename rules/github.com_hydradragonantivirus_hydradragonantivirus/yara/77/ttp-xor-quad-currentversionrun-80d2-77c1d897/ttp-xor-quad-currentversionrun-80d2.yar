rule TTP_XOR_QUAD_CurrentVersionRun_80d2 {
  strings:
    $key_80d2 = { d3 bd [2] f7 b3 [2] dc 9f [2] f2 bd [2] e6 a6 [2] e9 bc [2] f7 a1 [2] f5 a0 [2] ee a6 [2] f2 a1 [2] ee 8e }

  condition:
    any of them
}