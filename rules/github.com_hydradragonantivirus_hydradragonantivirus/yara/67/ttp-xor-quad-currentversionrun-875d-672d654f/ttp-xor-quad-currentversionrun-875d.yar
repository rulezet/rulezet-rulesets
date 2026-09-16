rule TTP_XOR_QUAD_CurrentVersionRun_875d {
  strings:
    $key_875d = { d4 32 [2] f0 3c [2] db 10 [2] f5 32 [2] e1 29 [2] ee 33 [2] f0 2e [2] f2 2f [2] e9 29 [2] f5 2e [2] e9 01 }

  condition:
    any of them
}