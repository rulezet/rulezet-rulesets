rule TTP_XOR_QUAD_CurrentVersionRun_8736 {
  strings:
    $key_8736 = { d4 59 [2] f0 57 [2] db 7b [2] f5 59 [2] e1 42 [2] ee 58 [2] f0 45 [2] f2 44 [2] e9 42 [2] f5 45 [2] e9 6a }

  condition:
    any of them
}