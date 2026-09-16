rule TTP_XOR_QUAD_CurrentVersionRun_99b0 {
  strings:
    $key_99b0 = { ca df [2] ee d1 [2] c5 fd [2] eb df [2] ff c4 [2] f0 de [2] ee c3 [2] ec c2 [2] f7 c4 [2] eb c3 [2] f7 ec }

  condition:
    any of them
}