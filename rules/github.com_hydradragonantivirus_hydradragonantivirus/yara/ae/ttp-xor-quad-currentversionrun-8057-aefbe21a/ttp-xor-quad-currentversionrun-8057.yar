rule TTP_XOR_QUAD_CurrentVersionRun_8057 {
  strings:
    $key_8057 = { d3 38 [2] f7 36 [2] dc 1a [2] f2 38 [2] e6 23 [2] e9 39 [2] f7 24 [2] f5 25 [2] ee 23 [2] f2 24 [2] ee 0b }

  condition:
    any of them
}