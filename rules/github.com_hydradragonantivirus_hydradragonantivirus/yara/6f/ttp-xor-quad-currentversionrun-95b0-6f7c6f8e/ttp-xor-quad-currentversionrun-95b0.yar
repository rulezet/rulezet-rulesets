rule TTP_XOR_QUAD_CurrentVersionRun_95b0 {
  strings:
    $key_95b0 = { c6 df [2] e2 d1 [2] c9 fd [2] e7 df [2] f3 c4 [2] fc de [2] e2 c3 [2] e0 c2 [2] fb c4 [2] e7 c3 [2] fb ec }

  condition:
    any of them
}