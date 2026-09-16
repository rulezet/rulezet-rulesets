rule TTP_XOR_QUAD_CurrentVersionRun_875b {
  strings:
    $key_875b = { d4 34 [2] f0 3a [2] db 16 [2] f5 34 [2] e1 2f [2] ee 35 [2] f0 28 [2] f2 29 [2] e9 2f [2] f5 28 [2] e9 07 }

  condition:
    any of them
}