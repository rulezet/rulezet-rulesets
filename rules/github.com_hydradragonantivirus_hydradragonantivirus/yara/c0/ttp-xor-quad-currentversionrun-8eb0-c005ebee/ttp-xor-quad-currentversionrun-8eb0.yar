rule TTP_XOR_QUAD_CurrentVersionRun_8eb0 {
  strings:
    $key_8eb0 = { dd df [2] f9 d1 [2] d2 fd [2] fc df [2] e8 c4 [2] e7 de [2] f9 c3 [2] fb c2 [2] e0 c4 [2] fc c3 [2] e0 ec }

  condition:
    any of them
}