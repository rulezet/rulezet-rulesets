rule TTP_XOR_QUAD_CurrentVersionRun_870d {
  strings:
    $key_870d = { d4 62 [2] f0 6c [2] db 40 [2] f5 62 [2] e1 79 [2] ee 63 [2] f0 7e [2] f2 7f [2] e9 79 [2] f5 7e [2] e9 51 }

  condition:
    any of them
}