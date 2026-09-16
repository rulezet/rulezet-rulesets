rule TTP_XOR_QUAD_CurrentVersionRun_875f {
  strings:
    $key_875f = { d4 30 [2] f0 3e [2] db 12 [2] f5 30 [2] e1 2b [2] ee 31 [2] f0 2c [2] f2 2d [2] e9 2b [2] f5 2c [2] e9 03 }

  condition:
    any of them
}