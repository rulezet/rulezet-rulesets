rule TTP_XOR_QUAD_CurrentVersionRun_8713 {
  strings:
    $key_8713 = { d4 7c [2] f0 72 [2] db 5e [2] f5 7c [2] e1 67 [2] ee 7d [2] f0 60 [2] f2 61 [2] e9 67 [2] f5 60 [2] e9 4f }

  condition:
    any of them
}