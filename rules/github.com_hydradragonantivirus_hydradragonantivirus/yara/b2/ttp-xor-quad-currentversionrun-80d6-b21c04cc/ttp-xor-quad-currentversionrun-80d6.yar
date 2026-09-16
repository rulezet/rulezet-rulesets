rule TTP_XOR_QUAD_CurrentVersionRun_80d6 {
  strings:
    $key_80d6 = { d3 b9 [2] f7 b7 [2] dc 9b [2] f2 b9 [2] e6 a2 [2] e9 b8 [2] f7 a5 [2] f5 a4 [2] ee a2 [2] f2 a5 [2] ee 8a }

  condition:
    any of them
}