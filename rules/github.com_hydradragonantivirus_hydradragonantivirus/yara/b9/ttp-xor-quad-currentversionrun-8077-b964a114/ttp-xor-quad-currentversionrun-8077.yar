rule TTP_XOR_QUAD_CurrentVersionRun_8077 {
  strings:
    $key_8077 = { d3 18 [2] f7 16 [2] dc 3a [2] f2 18 [2] e6 03 [2] e9 19 [2] f7 04 [2] f5 05 [2] ee 03 [2] f2 04 [2] ee 2b }

  condition:
    any of them
}