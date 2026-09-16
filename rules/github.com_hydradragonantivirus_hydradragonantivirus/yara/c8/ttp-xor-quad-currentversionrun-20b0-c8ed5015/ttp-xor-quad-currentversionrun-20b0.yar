rule TTP_XOR_QUAD_CurrentVersionRun_20b0 {
  strings:
    $key_20b0 = { 73 df [2] 57 d1 [2] 7c fd [2] 52 df [2] 46 c4 [2] 49 de [2] 57 c3 [2] 55 c2 [2] 4e c4 [2] 52 c3 [2] 4e ec }

  condition:
    any of them
}