rule TTP_XOR_QUAD_CurrentVersionRun_8737 {
  strings:
    $key_8737 = { d4 58 [2] f0 56 [2] db 7a [2] f5 58 [2] e1 43 [2] ee 59 [2] f0 44 [2] f2 45 [2] e9 43 [2] f5 44 [2] e9 6b }

  condition:
    any of them
}