rule TTP_XOR_QUAD_CurrentVersionRun_873f {
  strings:
    $key_873f = { d4 50 [2] f0 5e [2] db 72 [2] f5 50 [2] e1 4b [2] ee 51 [2] f0 4c [2] f2 4d [2] e9 4b [2] f5 4c [2] e9 63 }

  condition:
    any of them
}