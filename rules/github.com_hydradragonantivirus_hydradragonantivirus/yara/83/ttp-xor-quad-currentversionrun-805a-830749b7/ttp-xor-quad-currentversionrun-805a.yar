rule TTP_XOR_QUAD_CurrentVersionRun_805a {
  strings:
    $key_805a = { d3 35 [2] f7 3b [2] dc 17 [2] f2 35 [2] e6 2e [2] e9 34 [2] f7 29 [2] f5 28 [2] ee 2e [2] f2 29 [2] ee 06 }

  condition:
    any of them
}