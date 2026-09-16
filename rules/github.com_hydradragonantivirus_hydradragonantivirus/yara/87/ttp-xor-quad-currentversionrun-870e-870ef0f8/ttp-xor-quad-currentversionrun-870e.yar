rule TTP_XOR_QUAD_CurrentVersionRun_870e {
  strings:
    $key_870e = { d4 61 [2] f0 6f [2] db 43 [2] f5 61 [2] e1 7a [2] ee 60 [2] f0 7d [2] f2 7c [2] e9 7a [2] f5 7d [2] e9 52 }

  condition:
    any of them
}