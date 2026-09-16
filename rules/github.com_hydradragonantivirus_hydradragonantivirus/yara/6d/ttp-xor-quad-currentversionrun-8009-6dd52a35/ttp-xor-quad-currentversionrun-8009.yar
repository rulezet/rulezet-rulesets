rule TTP_XOR_QUAD_CurrentVersionRun_8009 {
  strings:
    $key_8009 = { d3 66 [2] f7 68 [2] dc 44 [2] f2 66 [2] e6 7d [2] e9 67 [2] f7 7a [2] f5 7b [2] ee 7d [2] f2 7a [2] ee 55 }

  condition:
    any of them
}