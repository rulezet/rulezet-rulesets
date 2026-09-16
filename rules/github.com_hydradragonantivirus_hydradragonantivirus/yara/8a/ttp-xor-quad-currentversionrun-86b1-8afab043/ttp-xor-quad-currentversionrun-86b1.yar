rule TTP_XOR_QUAD_CurrentVersionRun_86b1 {
  strings:
    $key_86b1 = { d5 de [2] f1 d0 [2] da fc [2] f4 de [2] e0 c5 [2] ef df [2] f1 c2 [2] f3 c3 [2] e8 c5 [2] f4 c2 [2] e8 ed }

  condition:
    any of them
}