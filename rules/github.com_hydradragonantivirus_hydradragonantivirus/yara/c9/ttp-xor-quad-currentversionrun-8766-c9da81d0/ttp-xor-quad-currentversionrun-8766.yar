rule TTP_XOR_QUAD_CurrentVersionRun_8766 {
  strings:
    $key_8766 = { d4 09 [2] f0 07 [2] db 2b [2] f5 09 [2] e1 12 [2] ee 08 [2] f0 15 [2] f2 14 [2] e9 12 [2] f5 15 [2] e9 3a }

  condition:
    any of them
}