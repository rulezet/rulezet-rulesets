rule TTP_XOR_QUAD_CurrentVersionRun_87e5 {
  strings:
    $key_87e5 = { d4 8a [2] f0 84 [2] db a8 [2] f5 8a [2] e1 91 [2] ee 8b [2] f0 96 [2] f2 97 [2] e9 91 [2] f5 96 [2] e9 b9 }

  condition:
    any of them
}