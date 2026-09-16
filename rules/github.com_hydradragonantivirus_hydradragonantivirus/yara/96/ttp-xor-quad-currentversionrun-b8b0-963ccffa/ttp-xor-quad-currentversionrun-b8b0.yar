rule TTP_XOR_QUAD_CurrentVersionRun_b8b0 {
  strings:
    $key_b8b0 = { eb df [2] cf d1 [2] e4 fd [2] ca df [2] de c4 [2] d1 de [2] cf c3 [2] cd c2 [2] d6 c4 [2] ca c3 [2] d6 ec }

  condition:
    any of them
}