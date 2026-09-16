rule TTP_XOR_QUAD_CurrentVersionRun_87f3 {
  strings:
    $key_87f3 = { d4 9c [2] f0 92 [2] db be [2] f5 9c [2] e1 87 [2] ee 9d [2] f0 80 [2] f2 81 [2] e9 87 [2] f5 80 [2] e9 af }

  condition:
    any of them
}