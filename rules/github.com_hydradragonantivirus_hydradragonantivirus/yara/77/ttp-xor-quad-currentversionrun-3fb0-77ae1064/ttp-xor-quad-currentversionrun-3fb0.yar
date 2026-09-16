rule TTP_XOR_QUAD_CurrentVersionRun_3fb0 {
  strings:
    $key_3fb0 = { 6c df [2] 48 d1 [2] 63 fd [2] 4d df [2] 59 c4 [2] 56 de [2] 48 c3 [2] 4a c2 [2] 51 c4 [2] 4d c3 [2] 51 ec }

  condition:
    any of them
}