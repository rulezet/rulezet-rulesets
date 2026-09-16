rule TTP_XOR_QUAD_CurrentVersionRun_878b {
  strings:
    $key_878b = { d4 e4 [2] f0 ea [2] db c6 [2] f5 e4 [2] e1 ff [2] ee e5 [2] f0 f8 [2] f2 f9 [2] e9 ff [2] f5 f8 [2] e9 d7 }

  condition:
    any of them
}