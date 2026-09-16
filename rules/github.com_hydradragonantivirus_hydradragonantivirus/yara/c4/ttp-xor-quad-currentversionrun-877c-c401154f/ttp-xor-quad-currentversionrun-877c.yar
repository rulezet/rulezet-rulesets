rule TTP_XOR_QUAD_CurrentVersionRun_877c {
  strings:
    $key_877c = { d4 13 [2] f0 1d [2] db 31 [2] f5 13 [2] e1 08 [2] ee 12 [2] f0 0f [2] f2 0e [2] e9 08 [2] f5 0f [2] e9 20 }

  condition:
    any of them
}