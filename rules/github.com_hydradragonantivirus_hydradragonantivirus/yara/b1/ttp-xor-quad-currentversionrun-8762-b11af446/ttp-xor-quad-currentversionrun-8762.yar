rule TTP_XOR_QUAD_CurrentVersionRun_8762 {
  strings:
    $key_8762 = { d4 0d [2] f0 03 [2] db 2f [2] f5 0d [2] e1 16 [2] ee 0c [2] f0 11 [2] f2 10 [2] e9 16 [2] f5 11 [2] e9 3e }

  condition:
    any of them
}