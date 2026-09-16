rule TTP_XOR_QUAD_CurrentVersionRun_8489 {
  strings:
    $key_8489 = { d7 e6 [2] f3 e8 [2] d8 c4 [2] f6 e6 [2] e2 fd [2] ed e7 [2] f3 fa [2] f1 fb [2] ea fd [2] f6 fa [2] ea d5 }

  condition:
    any of them
}