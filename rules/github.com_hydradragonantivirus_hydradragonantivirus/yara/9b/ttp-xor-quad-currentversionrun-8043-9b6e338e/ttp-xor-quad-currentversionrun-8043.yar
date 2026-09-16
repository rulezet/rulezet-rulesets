rule TTP_XOR_QUAD_CurrentVersionRun_8043 {
  strings:
    $key_8043 = { d3 2c [2] f7 22 [2] dc 0e [2] f2 2c [2] e6 37 [2] e9 2d [2] f7 30 [2] f5 31 [2] ee 37 [2] f2 30 [2] ee 1f }

  condition:
    any of them
}