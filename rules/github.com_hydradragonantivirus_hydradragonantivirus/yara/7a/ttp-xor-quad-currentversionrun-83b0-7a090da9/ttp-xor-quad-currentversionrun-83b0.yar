rule TTP_XOR_QUAD_CurrentVersionRun_83b0 {
  strings:
    $key_83b0 = { d0 df [2] f4 d1 [2] df fd [2] f1 df [2] e5 c4 [2] ea de [2] f4 c3 [2] f6 c2 [2] ed c4 [2] f1 c3 [2] ed ec }

  condition:
    any of them
}