rule TTP_XOR_QUAD_CurrentVersionRun_bdb0 {
  strings:
    $key_bdb0 = { ee df [2] ca d1 [2] e1 fd [2] cf df [2] db c4 [2] d4 de [2] ca c3 [2] c8 c2 [2] d3 c4 [2] cf c3 [2] d3 ec }

  condition:
    any of them
}