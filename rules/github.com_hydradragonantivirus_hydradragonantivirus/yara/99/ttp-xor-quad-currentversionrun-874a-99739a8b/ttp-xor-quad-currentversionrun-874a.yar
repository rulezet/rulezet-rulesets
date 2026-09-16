rule TTP_XOR_QUAD_CurrentVersionRun_874a {
  strings:
    $key_874a = { d4 25 [2] f0 2b [2] db 07 [2] f5 25 [2] e1 3e [2] ee 24 [2] f0 39 [2] f2 38 [2] e9 3e [2] f5 39 [2] e9 16 }

  condition:
    any of them
}