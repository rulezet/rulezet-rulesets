rule TTP_XOR_QUAD_CurrentVersionRun_870f {
  strings:
    $key_870f = { d4 60 [2] f0 6e [2] db 42 [2] f5 60 [2] e1 7b [2] ee 61 [2] f0 7c [2] f2 7d [2] e9 7b [2] f5 7c [2] e9 53 }

  condition:
    any of them
}