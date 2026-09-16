rule TTP_XOR_QUAD_CurrentVersionRun_8028 {
  strings:
    $key_8028 = { d3 47 [2] f7 49 [2] dc 65 [2] f2 47 [2] e6 5c [2] e9 46 [2] f7 5b [2] f5 5a [2] ee 5c [2] f2 5b [2] ee 74 }

  condition:
    any of them
}