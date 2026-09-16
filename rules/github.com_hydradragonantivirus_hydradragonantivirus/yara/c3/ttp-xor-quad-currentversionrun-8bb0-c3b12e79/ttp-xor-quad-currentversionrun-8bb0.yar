rule TTP_XOR_QUAD_CurrentVersionRun_8bb0 {
  strings:
    $key_8bb0 = { d8 df [2] fc d1 [2] d7 fd [2] f9 df [2] ed c4 [2] e2 de [2] fc c3 [2] fe c2 [2] e5 c4 [2] f9 c3 [2] e5 ec }

  condition:
    any of them
}