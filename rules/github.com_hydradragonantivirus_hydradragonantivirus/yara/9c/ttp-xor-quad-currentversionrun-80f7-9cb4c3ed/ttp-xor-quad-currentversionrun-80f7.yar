rule TTP_XOR_QUAD_CurrentVersionRun_80f7 {
  strings:
    $key_80f7 = { d3 98 [2] f7 96 [2] dc ba [2] f2 98 [2] e6 83 [2] e9 99 [2] f7 84 [2] f5 85 [2] ee 83 [2] f2 84 [2] ee ab }

  condition:
    any of them
}