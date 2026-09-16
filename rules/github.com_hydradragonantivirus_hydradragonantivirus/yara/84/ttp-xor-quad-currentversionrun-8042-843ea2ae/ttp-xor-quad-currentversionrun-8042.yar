rule TTP_XOR_QUAD_CurrentVersionRun_8042 {
  strings:
    $key_8042 = { d3 2d [2] f7 23 [2] dc 0f [2] f2 2d [2] e6 36 [2] e9 2c [2] f7 31 [2] f5 30 [2] ee 36 [2] f2 31 [2] ee 1e }

  condition:
    any of them
}