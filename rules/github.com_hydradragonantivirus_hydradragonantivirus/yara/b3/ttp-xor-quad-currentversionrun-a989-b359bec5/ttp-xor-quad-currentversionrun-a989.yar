rule TTP_XOR_QUAD_CurrentVersionRun_a989 {
  strings:
    $key_a989 = { fa e6 [2] de e8 [2] f5 c4 [2] db e6 [2] cf fd [2] c0 e7 [2] de fa [2] dc fb [2] c7 fd [2] db fa [2] c7 d5 }

  condition:
    any of them
}