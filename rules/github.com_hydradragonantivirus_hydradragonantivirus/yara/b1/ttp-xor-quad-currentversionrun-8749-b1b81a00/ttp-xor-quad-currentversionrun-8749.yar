rule TTP_XOR_QUAD_CurrentVersionRun_8749 {
  strings:
    $key_8749 = { d4 26 [2] f0 28 [2] db 04 [2] f5 26 [2] e1 3d [2] ee 27 [2] f0 3a [2] f2 3b [2] e9 3d [2] f5 3a [2] e9 15 }

  condition:
    any of them
}