rule TTP_XOR_QUAD_CurrentVersionRun_65b0 {
  strings:
    $key_65b0 = { 36 df [2] 12 d1 [2] 39 fd [2] 17 df [2] 03 c4 [2] 0c de [2] 12 c3 [2] 10 c2 [2] 0b c4 [2] 17 c3 [2] 0b ec }

  condition:
    any of them
}