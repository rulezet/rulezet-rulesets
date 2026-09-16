rule TTP_XOR_QUAD_CurrentVersionRun_803e {
  strings:
    $key_803e = { d3 51 [2] f7 5f [2] dc 73 [2] f2 51 [2] e6 4a [2] e9 50 [2] f7 4d [2] f5 4c [2] ee 4a [2] f2 4d [2] ee 62 }

  condition:
    any of them
}