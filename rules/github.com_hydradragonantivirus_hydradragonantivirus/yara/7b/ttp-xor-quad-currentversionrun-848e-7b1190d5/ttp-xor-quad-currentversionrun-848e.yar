rule TTP_XOR_QUAD_CurrentVersionRun_848e {
  strings:
    $key_848e = { d7 e1 [2] f3 ef [2] d8 c3 [2] f6 e1 [2] e2 fa [2] ed e0 [2] f3 fd [2] f1 fc [2] ea fa [2] f6 fd [2] ea d2 }

  condition:
    any of them
}