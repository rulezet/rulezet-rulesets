rule TTP_XOR_QUAD_CurrentVersionRun_876e {
  strings:
    $key_876e = { d4 01 [2] f0 0f [2] db 23 [2] f5 01 [2] e1 1a [2] ee 00 [2] f0 1d [2] f2 1c [2] e9 1a [2] f5 1d [2] e9 32 }

  condition:
    any of them
}