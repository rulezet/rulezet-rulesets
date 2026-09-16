rule TTP_XOR_QUAD_CurrentVersionRun_24b0 {
  strings:
    $key_24b0 = { 77 df [2] 53 d1 [2] 78 fd [2] 56 df [2] 42 c4 [2] 4d de [2] 53 c3 [2] 51 c2 [2] 4a c4 [2] 56 c3 [2] 4a ec }

  condition:
    any of them
}