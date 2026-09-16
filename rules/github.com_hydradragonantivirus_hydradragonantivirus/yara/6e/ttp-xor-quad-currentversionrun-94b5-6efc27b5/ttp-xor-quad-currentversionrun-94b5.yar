rule TTP_XOR_QUAD_CurrentVersionRun_94b5 {
  strings:
    $key_94b5 = { c7 da [2] e3 d4 [2] c8 f8 [2] e6 da [2] f2 c1 [2] fd db [2] e3 c6 [2] e1 c7 [2] fa c1 [2] e6 c6 [2] fa e9 }

  condition:
    any of them
}