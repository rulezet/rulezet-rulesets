rule TTP_XOR_QUAD_CurrentVersionRun_8708 {
  strings:
    $key_8708 = { d4 67 [2] f0 69 [2] db 45 [2] f5 67 [2] e1 7c [2] ee 66 [2] f0 7b [2] f2 7a [2] e9 7c [2] f5 7b [2] e9 54 }

  condition:
    any of them
}