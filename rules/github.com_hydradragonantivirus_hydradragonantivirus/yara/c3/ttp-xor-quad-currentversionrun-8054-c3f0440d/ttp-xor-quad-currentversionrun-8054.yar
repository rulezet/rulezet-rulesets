rule TTP_XOR_QUAD_CurrentVersionRun_8054 {
  strings:
    $key_8054 = { d3 3b [2] f7 35 [2] dc 19 [2] f2 3b [2] e6 20 [2] e9 3a [2] f7 27 [2] f5 26 [2] ee 20 [2] f2 27 [2] ee 08 }

  condition:
    any of them
}