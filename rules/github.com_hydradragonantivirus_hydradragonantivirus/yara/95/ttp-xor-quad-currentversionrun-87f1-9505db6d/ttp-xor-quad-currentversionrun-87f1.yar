rule TTP_XOR_QUAD_CurrentVersionRun_87f1 {
  strings:
    $key_87f1 = { d4 9e [2] f0 90 [2] db bc [2] f5 9e [2] e1 85 [2] ee 9f [2] f0 82 [2] f2 83 [2] e9 85 [2] f5 82 [2] e9 ad }

  condition:
    any of them
}