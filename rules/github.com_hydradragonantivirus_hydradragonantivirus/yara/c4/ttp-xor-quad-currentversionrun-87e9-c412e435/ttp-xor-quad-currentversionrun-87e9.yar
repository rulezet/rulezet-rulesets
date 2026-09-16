rule TTP_XOR_QUAD_CurrentVersionRun_87e9 {
  strings:
    $key_87e9 = { d4 86 [2] f0 88 [2] db a4 [2] f5 86 [2] e1 9d [2] ee 87 [2] f0 9a [2] f2 9b [2] e9 9d [2] f5 9a [2] e9 b5 }

  condition:
    any of them
}