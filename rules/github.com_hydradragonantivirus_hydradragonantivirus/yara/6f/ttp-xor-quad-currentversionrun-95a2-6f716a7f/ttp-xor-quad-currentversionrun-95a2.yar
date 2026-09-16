rule TTP_XOR_QUAD_CurrentVersionRun_95a2 {
  strings:
    $key_95a2 = { c6 cd [2] e2 c3 [2] c9 ef [2] e7 cd [2] f3 d6 [2] fc cc [2] e2 d1 [2] e0 d0 [2] fb d6 [2] e7 d1 [2] fb fe }

  condition:
    any of them
}