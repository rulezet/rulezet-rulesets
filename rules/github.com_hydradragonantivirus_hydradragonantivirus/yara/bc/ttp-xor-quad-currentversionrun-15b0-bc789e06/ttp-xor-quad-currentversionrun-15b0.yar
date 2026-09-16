rule TTP_XOR_QUAD_CurrentVersionRun_15b0 {
  strings:
    $key_15b0 = { 46 df [2] 62 d1 [2] 49 fd [2] 67 df [2] 73 c4 [2] 7c de [2] 62 c3 [2] 60 c2 [2] 7b c4 [2] 67 c3 [2] 7b ec }

  condition:
    any of them
}