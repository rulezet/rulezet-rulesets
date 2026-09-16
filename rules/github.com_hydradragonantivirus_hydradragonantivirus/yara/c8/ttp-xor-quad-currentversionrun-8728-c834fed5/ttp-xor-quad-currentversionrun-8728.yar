rule TTP_XOR_QUAD_CurrentVersionRun_8728 {
  strings:
    $key_8728 = { d4 47 [2] f0 49 [2] db 65 [2] f5 47 [2] e1 5c [2] ee 46 [2] f0 5b [2] f2 5a [2] e9 5c [2] f5 5b [2] e9 74 }

  condition:
    any of them
}