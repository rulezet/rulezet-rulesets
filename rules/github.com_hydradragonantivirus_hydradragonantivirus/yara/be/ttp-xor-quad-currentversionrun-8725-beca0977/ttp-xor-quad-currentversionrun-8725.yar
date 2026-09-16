rule TTP_XOR_QUAD_CurrentVersionRun_8725 {
  strings:
    $key_8725 = { d4 4a [2] f0 44 [2] db 68 [2] f5 4a [2] e1 51 [2] ee 4b [2] f0 56 [2] f2 57 [2] e9 51 [2] f5 56 [2] e9 79 }

  condition:
    any of them
}