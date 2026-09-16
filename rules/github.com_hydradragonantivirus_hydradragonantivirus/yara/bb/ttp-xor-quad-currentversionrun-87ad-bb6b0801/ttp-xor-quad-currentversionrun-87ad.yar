rule TTP_XOR_QUAD_CurrentVersionRun_87ad {
  strings:
    $key_87ad = { d4 c2 [2] f0 cc [2] db e0 [2] f5 c2 [2] e1 d9 [2] ee c3 [2] f0 de [2] f2 df [2] e9 d9 [2] f5 de [2] e9 f1 }

  condition:
    any of them
}