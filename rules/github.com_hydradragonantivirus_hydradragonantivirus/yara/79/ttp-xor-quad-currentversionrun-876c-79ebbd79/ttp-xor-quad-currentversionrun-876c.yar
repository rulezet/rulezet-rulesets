rule TTP_XOR_QUAD_CurrentVersionRun_876c {
  strings:
    $key_876c = { d4 03 [2] f0 0d [2] db 21 [2] f5 03 [2] e1 18 [2] ee 02 [2] f0 1f [2] f2 1e [2] e9 18 [2] f5 1f [2] e9 30 }

  condition:
    any of them
}