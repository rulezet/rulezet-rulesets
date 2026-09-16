rule TTP_XOR_QUAD_CurrentVersionRun_87e8 {
  strings:
    $key_87e8 = { d4 87 [2] f0 89 [2] db a5 [2] f5 87 [2] e1 9c [2] ee 86 [2] f0 9b [2] f2 9a [2] e9 9c [2] f5 9b [2] e9 b4 }

  condition:
    any of them
}