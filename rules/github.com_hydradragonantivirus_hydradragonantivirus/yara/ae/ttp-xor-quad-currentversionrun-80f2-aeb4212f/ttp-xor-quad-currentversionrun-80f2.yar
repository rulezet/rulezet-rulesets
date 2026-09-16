rule TTP_XOR_QUAD_CurrentVersionRun_80f2 {
  strings:
    $key_80f2 = { d3 9d [2] f7 93 [2] dc bf [2] f2 9d [2] e6 86 [2] e9 9c [2] f7 81 [2] f5 80 [2] ee 86 [2] f2 81 [2] ee ae }

  condition:
    any of them
}