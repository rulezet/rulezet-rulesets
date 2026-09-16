rule TTP_XOR_QUAD_CurrentVersionRun_aeb0 {
  strings:
    $key_aeb0 = { fd df [2] d9 d1 [2] f2 fd [2] dc df [2] c8 c4 [2] c7 de [2] d9 c3 [2] db c2 [2] c0 c4 [2] dc c3 [2] c0 ec }

  condition:
    any of them
}