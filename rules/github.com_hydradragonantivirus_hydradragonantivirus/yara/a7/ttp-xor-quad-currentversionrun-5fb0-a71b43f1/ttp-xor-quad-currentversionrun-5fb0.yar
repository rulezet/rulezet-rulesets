rule TTP_XOR_QUAD_CurrentVersionRun_5fb0 {
  strings:
    $key_5fb0 = { 0c df [2] 28 d1 [2] 03 fd [2] 2d df [2] 39 c4 [2] 36 de [2] 28 c3 [2] 2a c2 [2] 31 c4 [2] 2d c3 [2] 31 ec }

  condition:
    any of them
}