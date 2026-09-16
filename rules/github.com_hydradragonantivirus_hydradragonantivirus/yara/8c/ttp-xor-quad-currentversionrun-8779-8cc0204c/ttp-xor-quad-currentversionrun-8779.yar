rule TTP_XOR_QUAD_CurrentVersionRun_8779 {
  strings:
    $key_8779 = { d4 16 [2] f0 18 [2] db 34 [2] f5 16 [2] e1 0d [2] ee 17 [2] f0 0a [2] f2 0b [2] e9 0d [2] f5 0a [2] e9 25 }

  condition:
    any of them
}