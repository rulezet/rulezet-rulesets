rule TTP_XOR_QUAD_CurrentVersionRun_42ad {
  strings:
    $key_42ad = { 11 c2 [2] 35 cc [2] 1e e0 [2] 30 c2 [2] 24 d9 [2] 2b c3 [2] 35 de [2] 37 df [2] 2c d9 [2] 30 de [2] 2c f1 }

  condition:
    any of them
}