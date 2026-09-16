rule TTP_XOR_QUAD_CurrentVersionRun_8750 {
  strings:
    $key_8750 = { d4 3f [2] f0 31 [2] db 1d [2] f5 3f [2] e1 24 [2] ee 3e [2] f0 23 [2] f2 22 [2] e9 24 [2] f5 23 [2] e9 0c }

  condition:
    any of them
}