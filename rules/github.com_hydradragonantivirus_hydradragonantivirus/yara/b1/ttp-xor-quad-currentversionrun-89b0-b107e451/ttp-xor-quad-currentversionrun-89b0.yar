rule TTP_XOR_QUAD_CurrentVersionRun_89b0 {
  strings:
    $key_89b0 = { da df [2] fe d1 [2] d5 fd [2] fb df [2] ef c4 [2] e0 de [2] fe c3 [2] fc c2 [2] e7 c4 [2] fb c3 [2] e7 ec }

  condition:
    any of them
}