rule TTP_XOR_QUAD_CurrentVersionRun_8014 {
  strings:
    $key_8014 = { d3 7b [2] f7 75 [2] dc 59 [2] f2 7b [2] e6 60 [2] e9 7a [2] f7 67 [2] f5 66 [2] ee 60 [2] f2 67 [2] ee 48 }

  condition:
    any of them
}