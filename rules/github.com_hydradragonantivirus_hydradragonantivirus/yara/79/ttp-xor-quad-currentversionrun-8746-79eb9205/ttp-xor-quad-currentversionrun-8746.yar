rule TTP_XOR_QUAD_CurrentVersionRun_8746 {
  strings:
    $key_8746 = { d4 29 [2] f0 27 [2] db 0b [2] f5 29 [2] e1 32 [2] ee 28 [2] f0 35 [2] f2 34 [2] e9 32 [2] f5 35 [2] e9 1a }

  condition:
    any of them
}