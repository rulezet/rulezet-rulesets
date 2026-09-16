rule TTP_XOR_QUAD_CurrentVersionRun_8742 {
  strings:
    $key_8742 = { d4 2d [2] f0 23 [2] db 0f [2] f5 2d [2] e1 36 [2] ee 2c [2] f0 31 [2] f2 30 [2] e9 36 [2] f5 31 [2] e9 1e }

  condition:
    any of them
}