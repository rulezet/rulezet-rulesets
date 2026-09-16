rule TTP_XOR_QUAD_CurrentVersionRun_8059 {
  strings:
    $key_8059 = { d3 36 [2] f7 38 [2] dc 14 [2] f2 36 [2] e6 2d [2] e9 37 [2] f7 2a [2] f5 2b [2] ee 2d [2] f2 2a [2] ee 05 }

  condition:
    any of them
}