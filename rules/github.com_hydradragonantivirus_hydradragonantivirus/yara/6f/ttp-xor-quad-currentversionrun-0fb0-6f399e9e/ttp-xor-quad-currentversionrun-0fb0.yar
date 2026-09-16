rule TTP_XOR_QUAD_CurrentVersionRun_0fb0 {
  strings:
    $key_0fb0 = { 5c df [2] 78 d1 [2] 53 fd [2] 7d df [2] 69 c4 [2] 66 de [2] 78 c3 [2] 7a c2 [2] 61 c4 [2] 7d c3 [2] 61 ec }

  condition:
    any of them
}