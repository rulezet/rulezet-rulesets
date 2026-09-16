rule TTP_XOR_QUAD_CurrentVersionRun_8701 {
  strings:
    $key_8701 = { d4 6e [2] f0 60 [2] db 4c [2] f5 6e [2] e1 75 [2] ee 6f [2] f0 72 [2] f2 73 [2] e9 75 [2] f5 72 [2] e9 5d }

  condition:
    any of them
}