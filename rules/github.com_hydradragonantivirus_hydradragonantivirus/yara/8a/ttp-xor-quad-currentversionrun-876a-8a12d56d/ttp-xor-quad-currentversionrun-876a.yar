rule TTP_XOR_QUAD_CurrentVersionRun_876a {
  strings:
    $key_876a = { d4 05 [2] f0 0b [2] db 27 [2] f5 05 [2] e1 1e [2] ee 04 [2] f0 19 [2] f2 18 [2] e9 1e [2] f5 19 [2] e9 36 }

  condition:
    any of them
}