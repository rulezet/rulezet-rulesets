rule TTP_XOR_QUAD_CurrentVersionRun_8765 {
  strings:
    $key_8765 = { d4 0a [2] f0 04 [2] db 28 [2] f5 0a [2] e1 11 [2] ee 0b [2] f0 16 [2] f2 17 [2] e9 11 [2] f5 16 [2] e9 39 }

  condition:
    any of them
}