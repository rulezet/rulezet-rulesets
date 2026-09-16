rule TTP_XOR_QUAD_CurrentVersionRun_8738 {
  strings:
    $key_8738 = { d4 57 [2] f0 59 [2] db 75 [2] f5 57 [2] e1 4c [2] ee 56 [2] f0 4b [2] f2 4a [2] e9 4c [2] f5 4b [2] e9 64 }

  condition:
    any of them
}