rule TTP_XOR_QUAD_CurrentVersionRun_8755 {
  strings:
    $key_8755 = { d4 3a [2] f0 34 [2] db 18 [2] f5 3a [2] e1 21 [2] ee 3b [2] f0 26 [2] f2 27 [2] e9 21 [2] f5 26 [2] e9 09 }

  condition:
    any of them
}