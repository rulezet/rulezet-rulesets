rule TTP_XOR_QUAD_CurrentVersionRun_83b1 {
  strings:
    $key_83b1 = { d0 de [2] f4 d0 [2] df fc [2] f1 de [2] e5 c5 [2] ea df [2] f4 c2 [2] f6 c3 [2] ed c5 [2] f1 c2 [2] ed ed }

  condition:
    any of them
}