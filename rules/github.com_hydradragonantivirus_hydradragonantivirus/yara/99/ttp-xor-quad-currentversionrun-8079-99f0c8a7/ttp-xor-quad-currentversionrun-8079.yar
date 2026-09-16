rule TTP_XOR_QUAD_CurrentVersionRun_8079 {
  strings:
    $key_8079 = { d3 16 [2] f7 18 [2] dc 34 [2] f2 16 [2] e6 0d [2] e9 17 [2] f7 0a [2] f5 0b [2] ee 0d [2] f2 0a [2] ee 25 }

  condition:
    any of them
}