rule TTP_XOR_QUAD_CurrentVersionRun_80ee {
  strings:
    $key_80ee = { d3 81 [2] f7 8f [2] dc a3 [2] f2 81 [2] e6 9a [2] e9 80 [2] f7 9d [2] f5 9c [2] ee 9a [2] f2 9d [2] ee b2 }

  condition:
    any of them
}