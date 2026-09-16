rule TTP_XOR_QUAD_CurrentVersionRun_8051 {
  strings:
    $key_8051 = { d3 3e [2] f7 30 [2] dc 1c [2] f2 3e [2] e6 25 [2] e9 3f [2] f7 22 [2] f5 23 [2] ee 25 [2] f2 22 [2] ee 0d }

  condition:
    any of them
}