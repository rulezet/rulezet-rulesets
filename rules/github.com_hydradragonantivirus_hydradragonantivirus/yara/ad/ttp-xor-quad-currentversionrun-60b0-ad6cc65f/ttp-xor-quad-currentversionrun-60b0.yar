rule TTP_XOR_QUAD_CurrentVersionRun_60b0 {
  strings:
    $key_60b0 = { 33 df [2] 17 d1 [2] 3c fd [2] 12 df [2] 06 c4 [2] 09 de [2] 17 c3 [2] 15 c2 [2] 0e c4 [2] 12 c3 [2] 0e ec }

  condition:
    any of them
}