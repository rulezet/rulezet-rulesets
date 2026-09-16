rule TTP_XOR_QUAD_CurrentVersionRun_95b4 {
  strings:
    $key_95b4 = { c6 db [2] e2 d5 [2] c9 f9 [2] e7 db [2] f3 c0 [2] fc da [2] e2 c7 [2] e0 c6 [2] fb c0 [2] e7 c7 [2] fb e8 }

  condition:
    any of them
}