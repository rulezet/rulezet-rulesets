rule TTP_XOR_QUAD_CurrentVersionRun_80c7 {
  strings:
    $key_80c7 = { d3 a8 [2] f7 a6 [2] dc 8a [2] f2 a8 [2] e6 b3 [2] e9 a9 [2] f7 b4 [2] f5 b5 [2] ee b3 [2] f2 b4 [2] ee 9b }

  condition:
    any of them
}