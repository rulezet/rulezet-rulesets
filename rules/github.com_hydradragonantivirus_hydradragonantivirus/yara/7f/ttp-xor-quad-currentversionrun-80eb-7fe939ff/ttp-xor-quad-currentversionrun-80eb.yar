rule TTP_XOR_QUAD_CurrentVersionRun_80eb {
  strings:
    $key_80eb = { d3 84 [2] f7 8a [2] dc a6 [2] f2 84 [2] e6 9f [2] e9 85 [2] f7 98 [2] f5 99 [2] ee 9f [2] f2 98 [2] ee b7 }

  condition:
    any of them
}