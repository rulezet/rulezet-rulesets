rule TTP_XOR_QUAD_CurrentVersionRun_8034 {
  strings:
    $key_8034 = { d3 5b [2] f7 55 [2] dc 79 [2] f2 5b [2] e6 40 [2] e9 5a [2] f7 47 [2] f5 46 [2] ee 40 [2] f2 47 [2] ee 68 }

  condition:
    any of them
}