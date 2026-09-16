rule TTP_XOR_QUAD_CurrentVersionRun_bda8 {
  strings:
    $key_bda8 = { ee c7 [2] ca c9 [2] e1 e5 [2] cf c7 [2] db dc [2] d4 c6 [2] ca db [2] c8 da [2] d3 dc [2] cf db [2] d3 f4 }

  condition:
    any of them
}