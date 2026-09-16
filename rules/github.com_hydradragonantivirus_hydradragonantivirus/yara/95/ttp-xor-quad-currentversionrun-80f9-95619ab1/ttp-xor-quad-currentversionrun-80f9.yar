rule TTP_XOR_QUAD_CurrentVersionRun_80f9 {
  strings:
    $key_80f9 = { d3 96 [2] f7 98 [2] dc b4 [2] f2 96 [2] e6 8d [2] e9 97 [2] f7 8a [2] f5 8b [2] ee 8d [2] f2 8a [2] ee a5 }

  condition:
    any of them
}