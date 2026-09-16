rule TTP_XOR_QUAD_CurrentVersionRun_87e7 {
  strings:
    $key_87e7 = { d4 88 [2] f0 86 [2] db aa [2] f5 88 [2] e1 93 [2] ee 89 [2] f0 94 [2] f2 95 [2] e9 93 [2] f5 94 [2] e9 bb }

  condition:
    any of them
}