rule TTP_XOR_QUAD_CurrentVersionRun_8745 {
  strings:
    $key_8745 = { d4 2a [2] f0 24 [2] db 08 [2] f5 2a [2] e1 31 [2] ee 2b [2] f0 36 [2] f2 37 [2] e9 31 [2] f5 36 [2] e9 19 }

  condition:
    any of them
}