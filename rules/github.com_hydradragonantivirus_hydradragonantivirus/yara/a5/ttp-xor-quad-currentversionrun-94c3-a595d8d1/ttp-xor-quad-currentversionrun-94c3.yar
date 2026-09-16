rule TTP_XOR_QUAD_CurrentVersionRun_94c3 {
  strings:
    $key_94c3 = { c7 ac [2] e3 a2 [2] c8 8e [2] e6 ac [2] f2 b7 [2] fd ad [2] e3 b0 [2] e1 b1 [2] fa b7 [2] e6 b0 [2] fa 9f }

  condition:
    any of them
}