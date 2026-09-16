rule TTP_XOR_QUAD_CurrentVersionRun_bdb4 {
  strings:
    $key_bdb4 = { ee db [2] ca d5 [2] e1 f9 [2] cf db [2] db c0 [2] d4 da [2] ca c7 [2] c8 c6 [2] d3 c0 [2] cf c7 [2] d3 e8 }

  condition:
    any of them
}