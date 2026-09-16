rule TTP_XOR_QUAD_CurrentVersionRun_874d {
  strings:
    $key_874d = { d4 22 [2] f0 2c [2] db 00 [2] f5 22 [2] e1 39 [2] ee 23 [2] f0 3e [2] f2 3f [2] e9 39 [2] f5 3e [2] e9 11 }

  condition:
    any of them
}