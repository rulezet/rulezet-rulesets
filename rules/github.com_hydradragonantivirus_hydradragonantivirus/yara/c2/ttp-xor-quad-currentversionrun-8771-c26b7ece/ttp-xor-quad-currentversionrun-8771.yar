rule TTP_XOR_QUAD_CurrentVersionRun_8771 {
  strings:
    $key_8771 = { d4 1e [2] f0 10 [2] db 3c [2] f5 1e [2] e1 05 [2] ee 1f [2] f0 02 [2] f2 03 [2] e9 05 [2] f5 02 [2] e9 2d }

  condition:
    any of them
}