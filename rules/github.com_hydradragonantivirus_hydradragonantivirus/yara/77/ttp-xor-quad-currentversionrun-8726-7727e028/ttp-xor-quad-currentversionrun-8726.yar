rule TTP_XOR_QUAD_CurrentVersionRun_8726 {
  strings:
    $key_8726 = { d4 49 [2] f0 47 [2] db 6b [2] f5 49 [2] e1 52 [2] ee 48 [2] f0 55 [2] f2 54 [2] e9 52 [2] f5 55 [2] e9 7a }

  condition:
    any of them
}