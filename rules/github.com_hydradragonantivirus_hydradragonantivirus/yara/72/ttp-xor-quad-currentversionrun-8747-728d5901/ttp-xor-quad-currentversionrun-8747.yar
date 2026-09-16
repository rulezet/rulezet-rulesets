rule TTP_XOR_QUAD_CurrentVersionRun_8747 {
  strings:
    $key_8747 = { d4 28 [2] f0 26 [2] db 0a [2] f5 28 [2] e1 33 [2] ee 29 [2] f0 34 [2] f2 35 [2] e9 33 [2] f5 34 [2] e9 1b }

  condition:
    any of them
}