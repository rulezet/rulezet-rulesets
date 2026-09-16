rule TTP_XOR_QUAD_CurrentVersionRun_47b0 {
  strings:
    $key_47b0 = { 14 df [2] 30 d1 [2] 1b fd [2] 35 df [2] 21 c4 [2] 2e de [2] 30 c3 [2] 32 c2 [2] 29 c4 [2] 35 c3 [2] 29 ec }

  condition:
    any of them
}