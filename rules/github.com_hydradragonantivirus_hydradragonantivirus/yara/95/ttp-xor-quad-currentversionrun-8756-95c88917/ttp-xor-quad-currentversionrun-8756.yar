rule TTP_XOR_QUAD_CurrentVersionRun_8756 {
  strings:
    $key_8756 = { d4 39 [2] f0 37 [2] db 1b [2] f5 39 [2] e1 22 [2] ee 38 [2] f0 25 [2] f2 24 [2] e9 22 [2] f5 25 [2] e9 0a }

  condition:
    any of them
}