rule TTP_XOR_QUAD_CurrentVersionRun_874b {
  strings:
    $key_874b = { d4 24 [2] f0 2a [2] db 06 [2] f5 24 [2] e1 3f [2] ee 25 [2] f0 38 [2] f2 39 [2] e9 3f [2] f5 38 [2] e9 17 }

  condition:
    any of them
}