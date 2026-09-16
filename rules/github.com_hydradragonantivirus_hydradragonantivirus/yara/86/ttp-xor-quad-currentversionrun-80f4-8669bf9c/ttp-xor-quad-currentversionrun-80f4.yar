rule TTP_XOR_QUAD_CurrentVersionRun_80f4 {
  strings:
    $key_80f4 = { d3 9b [2] f7 95 [2] dc b9 [2] f2 9b [2] e6 80 [2] e9 9a [2] f7 87 [2] f5 86 [2] ee 80 [2] f2 87 [2] ee a8 }

  condition:
    any of them
}