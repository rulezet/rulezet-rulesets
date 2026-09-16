rule TTP_XOR_QUAD_CurrentVersionRun_25b0 {
  strings:
    $key_25b0 = { 76 df [2] 52 d1 [2] 79 fd [2] 57 df [2] 43 c4 [2] 4c de [2] 52 c3 [2] 50 c2 [2] 4b c4 [2] 57 c3 [2] 4b ec }

  condition:
    any of them
}