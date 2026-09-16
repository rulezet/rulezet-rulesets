rule TTP_XOR_QUAD_CurrentVersionRun_8754 {
  strings:
    $key_8754 = { d4 3b [2] f0 35 [2] db 19 [2] f5 3b [2] e1 20 [2] ee 3a [2] f0 27 [2] f2 26 [2] e9 20 [2] f5 27 [2] e9 08 }

  condition:
    any of them
}