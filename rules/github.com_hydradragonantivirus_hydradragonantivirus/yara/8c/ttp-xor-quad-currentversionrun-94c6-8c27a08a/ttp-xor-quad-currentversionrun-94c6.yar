rule TTP_XOR_QUAD_CurrentVersionRun_94c6 {
  strings:
    $key_94c6 = { c7 a9 [2] e3 a7 [2] c8 8b [2] e6 a9 [2] f2 b2 [2] fd a8 [2] e3 b5 [2] e1 b4 [2] fa b2 [2] e6 b5 [2] fa 9a }

  condition:
    any of them
}