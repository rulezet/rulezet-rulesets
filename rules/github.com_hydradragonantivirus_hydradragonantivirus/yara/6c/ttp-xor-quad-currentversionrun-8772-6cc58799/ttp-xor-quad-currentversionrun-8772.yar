rule TTP_XOR_QUAD_CurrentVersionRun_8772 {
  strings:
    $key_8772 = { d4 1d [2] f0 13 [2] db 3f [2] f5 1d [2] e1 06 [2] ee 1c [2] f0 01 [2] f2 00 [2] e9 06 [2] f5 01 [2] e9 2e }

  condition:
    any of them
}