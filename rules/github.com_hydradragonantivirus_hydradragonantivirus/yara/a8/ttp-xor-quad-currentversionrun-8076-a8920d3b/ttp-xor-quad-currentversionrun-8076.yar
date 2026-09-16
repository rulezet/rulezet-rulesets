rule TTP_XOR_QUAD_CurrentVersionRun_8076 {
  strings:
    $key_8076 = { d3 19 [2] f7 17 [2] dc 3b [2] f2 19 [2] e6 02 [2] e9 18 [2] f7 05 [2] f5 04 [2] ee 02 [2] f2 05 [2] ee 2a }

  condition:
    any of them
}