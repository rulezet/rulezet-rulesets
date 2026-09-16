rule TTP_XOR_QUAD_CurrentVersionRun_871b {
  strings:
    $key_871b = { d4 74 [2] f0 7a [2] db 56 [2] f5 74 [2] e1 6f [2] ee 75 [2] f0 68 [2] f2 69 [2] e9 6f [2] f5 68 [2] e9 47 }

  condition:
    any of them
}