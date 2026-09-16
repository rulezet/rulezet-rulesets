rule TTP_XOR_QUAD_CurrentVersionRun_8719 {
  strings:
    $key_8719 = { d4 76 [2] f0 78 [2] db 54 [2] f5 76 [2] e1 6d [2] ee 77 [2] f0 6a [2] f2 6b [2] e9 6d [2] f5 6a [2] e9 45 }

  condition:
    any of them
}