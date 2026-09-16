rule TTP_XOR_QUAD_CurrentVersionRun_8710 {
  strings:
    $key_8710 = { d4 7f [2] f0 71 [2] db 5d [2] f5 7f [2] e1 64 [2] ee 7e [2] f0 63 [2] f2 62 [2] e9 64 [2] f5 63 [2] e9 4c }

  condition:
    any of them
}