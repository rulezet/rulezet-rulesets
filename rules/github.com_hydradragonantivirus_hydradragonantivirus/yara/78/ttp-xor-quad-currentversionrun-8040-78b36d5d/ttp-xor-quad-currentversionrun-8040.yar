rule TTP_XOR_QUAD_CurrentVersionRun_8040 {
  strings:
    $key_8040 = { d3 2f [2] f7 21 [2] dc 0d [2] f2 2f [2] e6 34 [2] e9 2e [2] f7 33 [2] f5 32 [2] ee 34 [2] f2 33 [2] ee 1c }

  condition:
    any of them
}