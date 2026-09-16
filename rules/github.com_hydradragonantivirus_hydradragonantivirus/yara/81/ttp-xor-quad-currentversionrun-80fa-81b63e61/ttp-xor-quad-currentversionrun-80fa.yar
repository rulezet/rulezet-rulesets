rule TTP_XOR_QUAD_CurrentVersionRun_80fa {
  strings:
    $key_80fa = { d3 95 [2] f7 9b [2] dc b7 [2] f2 95 [2] e6 8e [2] e9 94 [2] f7 89 [2] f5 88 [2] ee 8e [2] f2 89 [2] ee a6 }

  condition:
    any of them
}