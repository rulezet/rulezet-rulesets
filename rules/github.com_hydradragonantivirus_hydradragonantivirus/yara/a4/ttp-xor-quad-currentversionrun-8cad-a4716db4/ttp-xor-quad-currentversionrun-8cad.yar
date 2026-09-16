rule TTP_XOR_QUAD_CurrentVersionRun_8cad {
  strings:
    $key_8cad = { df c2 [2] fb cc [2] d0 e0 [2] fe c2 [2] ea d9 [2] e5 c3 [2] fb de [2] f9 df [2] e2 d9 [2] fe de [2] e2 f1 }

  condition:
    any of them
}