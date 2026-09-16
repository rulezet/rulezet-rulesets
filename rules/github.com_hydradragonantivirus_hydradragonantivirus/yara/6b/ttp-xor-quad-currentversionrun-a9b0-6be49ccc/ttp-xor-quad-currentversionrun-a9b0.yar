rule TTP_XOR_QUAD_CurrentVersionRun_a9b0 {
  strings:
    $key_a9b0 = { fa df [2] de d1 [2] f5 fd [2] db df [2] cf c4 [2] c0 de [2] de c3 [2] dc c2 [2] c7 c4 [2] db c3 [2] c7 ec }

  condition:
    any of them
}