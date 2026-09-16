rule TTP_XOR_QUAD_CurrentVersionRun_8fb0 {
  strings:
    $key_8fb0 = { dc df [2] f8 d1 [2] d3 fd [2] fd df [2] e9 c4 [2] e6 de [2] f8 c3 [2] fa c2 [2] e1 c4 [2] fd c3 [2] e1 ec }

  condition:
    any of them
}