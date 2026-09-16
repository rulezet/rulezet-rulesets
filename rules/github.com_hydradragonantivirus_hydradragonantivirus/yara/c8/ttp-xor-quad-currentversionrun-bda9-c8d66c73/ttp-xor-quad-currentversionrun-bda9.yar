rule TTP_XOR_QUAD_CurrentVersionRun_bda9 {
  strings:
    $key_bda9 = { ee c6 [2] ca c8 [2] e1 e4 [2] cf c6 [2] db dd [2] d4 c7 [2] ca da [2] c8 db [2] d3 dd [2] cf da [2] d3 f5 }

  condition:
    any of them
}