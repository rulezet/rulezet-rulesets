rule TTP_XOR_QUAD_CurrentVersionRun_1bb0 {
  strings:
    $key_1bb0 = { 48 df [2] 6c d1 [2] 47 fd [2] 69 df [2] 7d c4 [2] 72 de [2] 6c c3 [2] 6e c2 [2] 75 c4 [2] 69 c3 [2] 75 ec }

  condition:
    any of them
}