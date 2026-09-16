rule TTP_XOR_QUAD_CurrentVersionRun_8709 {
  strings:
    $key_8709 = { d4 66 [2] f0 68 [2] db 44 [2] f5 66 [2] e1 7d [2] ee 67 [2] f0 7a [2] f2 7b [2] e9 7d [2] f5 7a [2] e9 55 }

  condition:
    any of them
}