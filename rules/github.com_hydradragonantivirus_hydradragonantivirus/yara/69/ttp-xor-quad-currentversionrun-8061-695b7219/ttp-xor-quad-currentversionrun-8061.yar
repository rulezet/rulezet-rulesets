rule TTP_XOR_QUAD_CurrentVersionRun_8061 {
  strings:
    $key_8061 = { d3 0e [2] f7 00 [2] dc 2c [2] f2 0e [2] e6 15 [2] e9 0f [2] f7 12 [2] f5 13 [2] ee 15 [2] f2 12 [2] ee 3d }

  condition:
    any of them
}