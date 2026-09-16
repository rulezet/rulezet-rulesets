rule TTP_XOR_QUAD_CurrentVersionRun_877d {
  strings:
    $key_877d = { d4 12 [2] f0 1c [2] db 30 [2] f5 12 [2] e1 09 [2] ee 13 [2] f0 0e [2] f2 0f [2] e9 09 [2] f5 0e [2] e9 21 }

  condition:
    any of them
}