rule TTP_XOR_QUAD_CurrentVersionRun_bda7 {
  strings:
    $key_bda7 = { ee c8 [2] ca c6 [2] e1 ea [2] cf c8 [2] db d3 [2] d4 c9 [2] ca d4 [2] c8 d5 [2] d3 d3 [2] cf d4 [2] d3 fb }

  condition:
    any of them
}