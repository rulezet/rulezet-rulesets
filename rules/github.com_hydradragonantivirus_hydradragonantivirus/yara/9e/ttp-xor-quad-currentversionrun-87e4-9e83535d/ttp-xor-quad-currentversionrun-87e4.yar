rule TTP_XOR_QUAD_CurrentVersionRun_87e4 {
  strings:
    $key_87e4 = { d4 8b [2] f0 85 [2] db a9 [2] f5 8b [2] e1 90 [2] ee 8a [2] f0 97 [2] f2 96 [2] e9 90 [2] f5 97 [2] e9 b8 }

  condition:
    any of them
}