rule TTP_XOR_QUAD_CurrentVersionRun_805b {
  strings:
    $key_805b = { d3 34 [2] f7 3a [2] dc 16 [2] f2 34 [2] e6 2f [2] e9 35 [2] f7 28 [2] f5 29 [2] ee 2f [2] f2 28 [2] ee 07 }

  condition:
    any of them
}