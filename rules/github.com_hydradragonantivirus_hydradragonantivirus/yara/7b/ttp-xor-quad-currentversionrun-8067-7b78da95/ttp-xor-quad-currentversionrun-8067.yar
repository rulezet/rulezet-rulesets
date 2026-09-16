rule TTP_XOR_QUAD_CurrentVersionRun_8067 {
  strings:
    $key_8067 = { d3 08 [2] f7 06 [2] dc 2a [2] f2 08 [2] e6 13 [2] e9 09 [2] f7 14 [2] f5 15 [2] ee 13 [2] f2 14 [2] ee 3b }

  condition:
    any of them
}