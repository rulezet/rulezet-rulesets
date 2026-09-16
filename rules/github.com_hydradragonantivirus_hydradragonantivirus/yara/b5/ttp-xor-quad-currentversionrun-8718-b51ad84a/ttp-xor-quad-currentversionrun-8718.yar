rule TTP_XOR_QUAD_CurrentVersionRun_8718 {
  strings:
    $key_8718 = { d4 77 [2] f0 79 [2] db 55 [2] f5 77 [2] e1 6c [2] ee 76 [2] f0 6b [2] f2 6a [2] e9 6c [2] f5 6b [2] e9 44 }

  condition:
    any of them
}