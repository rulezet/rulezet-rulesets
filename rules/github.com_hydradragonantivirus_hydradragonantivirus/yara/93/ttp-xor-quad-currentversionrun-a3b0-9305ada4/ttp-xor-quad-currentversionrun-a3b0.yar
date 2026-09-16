rule TTP_XOR_QUAD_CurrentVersionRun_a3b0 {
  strings:
    $key_a3b0 = { f0 df [2] d4 d1 [2] ff fd [2] d1 df [2] c5 c4 [2] ca de [2] d4 c3 [2] d6 c2 [2] cd c4 [2] d1 c3 [2] cd ec }

  condition:
    any of them
}