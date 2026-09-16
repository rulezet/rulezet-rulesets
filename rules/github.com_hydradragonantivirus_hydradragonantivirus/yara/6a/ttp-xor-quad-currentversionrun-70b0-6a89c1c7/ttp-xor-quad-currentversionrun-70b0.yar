rule TTP_XOR_QUAD_CurrentVersionRun_70b0 {
  strings:
    $key_70b0 = { 23 df [2] 07 d1 [2] 2c fd [2] 02 df [2] 16 c4 [2] 19 de [2] 07 c3 [2] 05 c2 [2] 1e c4 [2] 02 c3 [2] 1e ec }

  condition:
    any of them
}