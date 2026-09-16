rule TTP_XOR_QUAD_CurrentVersionRun_876f {
  strings:
    $key_876f = { d4 00 [2] f0 0e [2] db 22 [2] f5 00 [2] e1 1b [2] ee 01 [2] f0 1c [2] f2 1d [2] e9 1b [2] f5 1c [2] e9 33 }

  condition:
    any of them
}