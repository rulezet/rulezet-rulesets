rule TTP_XOR_QUAD_CurrentVersionRun_7bb0 {
  strings:
    $key_7bb0 = { 28 df [2] 0c d1 [2] 27 fd [2] 09 df [2] 1d c4 [2] 12 de [2] 0c c3 [2] 0e c2 [2] 15 c4 [2] 09 c3 [2] 15 ec }

  condition:
    any of them
}