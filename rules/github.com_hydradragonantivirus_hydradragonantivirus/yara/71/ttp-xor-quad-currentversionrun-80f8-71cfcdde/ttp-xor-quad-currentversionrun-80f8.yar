rule TTP_XOR_QUAD_CurrentVersionRun_80f8 {
  strings:
    $key_80f8 = { d3 97 [2] f7 99 [2] dc b5 [2] f2 97 [2] e6 8c [2] e9 96 [2] f7 8b [2] f5 8a [2] ee 8c [2] f2 8b [2] ee a4 }

  condition:
    any of them
}