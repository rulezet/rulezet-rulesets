rule TTP_XOR_QUAD_CurrentVersionRun_876b {
  strings:
    $key_876b = { d4 04 [2] f0 0a [2] db 26 [2] f5 04 [2] e1 1f [2] ee 05 [2] f0 18 [2] f2 19 [2] e9 1f [2] f5 18 [2] e9 37 }

  condition:
    any of them
}