rule TTP_XOR_QUAD_CurrentVersionRun_8769 {
  strings:
    $key_8769 = { d4 06 [2] f0 08 [2] db 24 [2] f5 06 [2] e1 1d [2] ee 07 [2] f0 1a [2] f2 1b [2] e9 1d [2] f5 1a [2] e9 35 }

  condition:
    any of them
}