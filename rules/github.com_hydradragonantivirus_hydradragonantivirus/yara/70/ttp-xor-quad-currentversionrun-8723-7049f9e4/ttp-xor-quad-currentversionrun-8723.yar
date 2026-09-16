rule TTP_XOR_QUAD_CurrentVersionRun_8723 {
  strings:
    $key_8723 = { d4 4c [2] f0 42 [2] db 6e [2] f5 4c [2] e1 57 [2] ee 4d [2] f0 50 [2] f2 51 [2] e9 57 [2] f5 50 [2] e9 7f }

  condition:
    any of them
}