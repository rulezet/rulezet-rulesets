rule TTP_XOR_QUAD_CurrentVersionRun_8050 {
  strings:
    $key_8050 = { d3 3f [2] f7 31 [2] dc 1d [2] f2 3f [2] e6 24 [2] e9 3e [2] f7 23 [2] f5 22 [2] ee 24 [2] f2 23 [2] ee 0c }

  condition:
    any of them
}