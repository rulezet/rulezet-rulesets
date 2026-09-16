rule TTP_XOR_QUAD_CurrentVersionRun_871a {
  strings:
    $key_871a = { d4 75 [2] f0 7b [2] db 57 [2] f5 75 [2] e1 6e [2] ee 74 [2] f0 69 [2] f2 68 [2] e9 6e [2] f5 69 [2] e9 46 }

  condition:
    any of them
}