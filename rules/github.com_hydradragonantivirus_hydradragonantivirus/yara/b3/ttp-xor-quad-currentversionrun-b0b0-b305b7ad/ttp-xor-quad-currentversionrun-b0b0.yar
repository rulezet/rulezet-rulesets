rule TTP_XOR_QUAD_CurrentVersionRun_b0b0 {
  strings:
    $key_b0b0 = { e3 df [2] c7 d1 [2] ec fd [2] c2 df [2] d6 c4 [2] d9 de [2] c7 c3 [2] c5 c2 [2] de c4 [2] c2 c3 [2] de ec }

  condition:
    any of them
}