rule TTP_XOR_QUAD_CurrentVersionRun_8776 {
  strings:
    $key_8776 = { d4 19 [2] f0 17 [2] db 3b [2] f5 19 [2] e1 02 [2] ee 18 [2] f0 05 [2] f2 04 [2] e9 02 [2] f5 05 [2] e9 2a }

  condition:
    any of them
}