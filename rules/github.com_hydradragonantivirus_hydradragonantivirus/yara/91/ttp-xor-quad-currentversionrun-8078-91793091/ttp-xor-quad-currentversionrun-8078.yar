rule TTP_XOR_QUAD_CurrentVersionRun_8078 {
  strings:
    $key_8078 = { d3 17 [2] f7 19 [2] dc 35 [2] f2 17 [2] e6 0c [2] e9 16 [2] f7 0b [2] f5 0a [2] ee 0c [2] f2 0b [2] ee 24 }

  condition:
    any of them
}