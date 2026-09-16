rule TTP_XOR_QUAD_CurrentVersionRun_804b {
  strings:
    $key_804b = { d3 24 [2] f7 2a [2] dc 06 [2] f2 24 [2] e6 3f [2] e9 25 [2] f7 38 [2] f5 39 [2] ee 3f [2] f2 38 [2] ee 17 }

  condition:
    any of them
}