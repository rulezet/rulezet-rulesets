rule TTP_XOR_QUAD_CurrentVersionRun_42b0 {
  strings:
    $key_42b0 = { 11 df [2] 35 d1 [2] 1e fd [2] 30 df [2] 24 c4 [2] 2b de [2] 35 c3 [2] 37 c2 [2] 2c c4 [2] 30 c3 [2] 2c ec }

  condition:
    any of them
}