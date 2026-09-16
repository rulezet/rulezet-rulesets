rule TTP_XOR_QUAD_CurrentVersionRun_8055 {
  strings:
    $key_8055 = { d3 3a [2] f7 34 [2] dc 18 [2] f2 3a [2] e6 21 [2] e9 3b [2] f7 26 [2] f5 27 [2] ee 21 [2] f2 26 [2] ee 09 }

  condition:
    any of them
}