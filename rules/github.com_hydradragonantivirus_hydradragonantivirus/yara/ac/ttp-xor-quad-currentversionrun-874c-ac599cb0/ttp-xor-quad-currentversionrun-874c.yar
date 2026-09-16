rule TTP_XOR_QUAD_CurrentVersionRun_874c {
  strings:
    $key_874c = { d4 23 [2] f0 2d [2] db 01 [2] f5 23 [2] e1 38 [2] ee 22 [2] f0 3f [2] f2 3e [2] e9 38 [2] f5 3f [2] e9 10 }

  condition:
    any of them
}