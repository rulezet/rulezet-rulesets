rule TTP_XOR_QUAD_CurrentVersionRun_8007 {
  strings:
    $key_8007 = { d3 68 [2] f7 66 [2] dc 4a [2] f2 68 [2] e6 73 [2] e9 69 [2] f7 74 [2] f5 75 [2] ee 73 [2] f2 74 [2] ee 5b }

  condition:
    any of them
}