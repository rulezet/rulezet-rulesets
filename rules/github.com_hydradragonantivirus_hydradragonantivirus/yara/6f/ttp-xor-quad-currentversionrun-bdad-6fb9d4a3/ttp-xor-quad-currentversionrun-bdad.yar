rule TTP_XOR_QUAD_CurrentVersionRun_bdad {
  strings:
    $key_bdad = { ee c2 [2] ca cc [2] e1 e0 [2] cf c2 [2] db d9 [2] d4 c3 [2] ca de [2] c8 df [2] d3 d9 [2] cf de [2] d3 f1 }

  condition:
    any of them
}