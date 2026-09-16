rule TTP_XOR_QUAD_CurrentVersionRun_803c {
  strings:
    $key_803c = { d3 53 [2] f7 5d [2] dc 71 [2] f2 53 [2] e6 48 [2] e9 52 [2] f7 4f [2] f5 4e [2] ee 48 [2] f2 4f [2] ee 60 }

  condition:
    any of them
}