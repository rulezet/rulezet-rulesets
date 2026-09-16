rule TTP_XOR_QUAD_CurrentVersionRun_b3b0 {
  strings:
    $key_b3b0 = { e0 df [2] c4 d1 [2] ef fd [2] c1 df [2] d5 c4 [2] da de [2] c4 c3 [2] c6 c2 [2] dd c4 [2] c1 c3 [2] dd ec }

  condition:
    any of them
}