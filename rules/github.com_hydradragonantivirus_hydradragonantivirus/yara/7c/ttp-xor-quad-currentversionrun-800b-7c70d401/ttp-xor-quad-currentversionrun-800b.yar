rule TTP_XOR_QUAD_CurrentVersionRun_800b {
  strings:
    $key_800b = { d3 64 [2] f7 6a [2] dc 46 [2] f2 64 [2] e6 7f [2] e9 65 [2] f7 78 [2] f5 79 [2] ee 7f [2] f2 78 [2] ee 57 }

  condition:
    any of them
}