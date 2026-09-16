rule TTP_XOR_QUAD_CurrentVersionRun_8044 {
  strings:
    $key_8044 = { d3 2b [2] f7 25 [2] dc 09 [2] f2 2b [2] e6 30 [2] e9 2a [2] f7 37 [2] f5 36 [2] ee 30 [2] f2 37 [2] ee 18 }

  condition:
    any of them
}