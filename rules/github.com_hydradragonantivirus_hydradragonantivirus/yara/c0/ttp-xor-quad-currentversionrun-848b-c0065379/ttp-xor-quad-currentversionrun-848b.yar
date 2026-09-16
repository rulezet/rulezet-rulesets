rule TTP_XOR_QUAD_CurrentVersionRun_848b {
  strings:
    $key_848b = { d7 e4 [2] f3 ea [2] d8 c6 [2] f6 e4 [2] e2 ff [2] ed e5 [2] f3 f8 [2] f1 f9 [2] ea ff [2] f6 f8 [2] ea d7 }

  condition:
    any of them
}