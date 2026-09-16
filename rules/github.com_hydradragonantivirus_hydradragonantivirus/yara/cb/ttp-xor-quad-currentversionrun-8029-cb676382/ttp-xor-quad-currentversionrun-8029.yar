rule TTP_XOR_QUAD_CurrentVersionRun_8029 {
  strings:
    $key_8029 = { d3 46 [2] f7 48 [2] dc 64 [2] f2 46 [2] e6 5d [2] e9 47 [2] f7 5a [2] f5 5b [2] ee 5d [2] f2 5a [2] ee 75 }

  condition:
    any of them
}