rule TTP_XOR_QUAD_CurrentVersionRun_875c {
  strings:
    $key_875c = { d4 33 [2] f0 3d [2] db 11 [2] f5 33 [2] e1 28 [2] ee 32 [2] f0 2f [2] f2 2e [2] e9 28 [2] f5 2f [2] e9 00 }

  condition:
    any of them
}