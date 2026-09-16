rule TTP_XOR_QUAD_CurrentVersionRun_77b0 {
  strings:
    $key_77b0 = { 24 df [2] 00 d1 [2] 2b fd [2] 05 df [2] 11 c4 [2] 1e de [2] 00 c3 [2] 02 c2 [2] 19 c4 [2] 05 c3 [2] 19 ec }

  condition:
    any of them
}