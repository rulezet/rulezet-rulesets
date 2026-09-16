rule TTP_XOR_QUAD_CurrentVersionRun_877e {
  strings:
    $key_877e = { d4 11 [2] f0 1f [2] db 33 [2] f5 11 [2] e1 0a [2] ee 10 [2] f0 0d [2] f2 0c [2] e9 0a [2] f5 0d [2] e9 22 }

  condition:
    any of them
}