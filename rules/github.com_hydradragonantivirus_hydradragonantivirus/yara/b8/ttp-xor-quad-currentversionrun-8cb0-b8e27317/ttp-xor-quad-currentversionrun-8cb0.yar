rule TTP_XOR_QUAD_CurrentVersionRun_8cb0 {
  strings:
    $key_8cb0 = { df df [2] fb d1 [2] d0 fd [2] fe df [2] ea c4 [2] e5 de [2] fb c3 [2] f9 c2 [2] e2 c4 [2] fe c3 [2] e2 ec }

  condition:
    any of them
}