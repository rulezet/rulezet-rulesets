rule TTP_XOR_QUAD_CurrentVersionRun_64b0 {
  strings:
    $key_64b0 = { 37 df [2] 13 d1 [2] 38 fd [2] 16 df [2] 02 c4 [2] 0d de [2] 13 c3 [2] 11 c2 [2] 0a c4 [2] 16 c3 [2] 0a ec }

  condition:
    any of them
}