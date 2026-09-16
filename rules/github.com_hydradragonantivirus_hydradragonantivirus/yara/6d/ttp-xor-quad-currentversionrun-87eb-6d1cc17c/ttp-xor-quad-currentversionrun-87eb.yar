rule TTP_XOR_QUAD_CurrentVersionRun_87eb {
  strings:
    $key_87eb = { d4 84 [2] f0 8a [2] db a6 [2] f5 84 [2] e1 9f [2] ee 85 [2] f0 98 [2] f2 99 [2] e9 9f [2] f5 98 [2] e9 b7 }

  condition:
    any of them
}