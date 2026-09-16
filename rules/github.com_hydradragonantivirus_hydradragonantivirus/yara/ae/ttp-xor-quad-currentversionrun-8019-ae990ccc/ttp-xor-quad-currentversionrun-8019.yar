rule TTP_XOR_QUAD_CurrentVersionRun_8019 {
  strings:
    $key_8019 = { d3 76 [2] f7 78 [2] dc 54 [2] f2 76 [2] e6 6d [2] e9 77 [2] f7 6a [2] f5 6b [2] ee 6d [2] f2 6a [2] ee 45 }

  condition:
    any of them
}