rule TTP_XOR_QUAD_CurrentVersionRun_958e {
  strings:
    $key_958e = { c6 e1 [2] e2 ef [2] c9 c3 [2] e7 e1 [2] f3 fa [2] fc e0 [2] e2 fd [2] e0 fc [2] fb fa [2] e7 fd [2] fb d2 }

  condition:
    any of them
}