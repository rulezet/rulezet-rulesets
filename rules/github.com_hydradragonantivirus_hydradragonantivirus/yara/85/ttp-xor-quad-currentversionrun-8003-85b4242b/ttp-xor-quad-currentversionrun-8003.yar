rule TTP_XOR_QUAD_CurrentVersionRun_8003 {
  strings:
    $key_8003 = { d3 6c [2] f7 62 [2] dc 4e [2] f2 6c [2] e6 77 [2] e9 6d [2] f7 70 [2] f5 71 [2] ee 77 [2] f2 70 [2] ee 5f }

  condition:
    any of them
}