rule TTP_XOR_QUAD_CurrentVersionRun_fbb0 {
  strings:
    $key_fbb0 = { a8 df [2] 8c d1 [2] a7 fd [2] 89 df [2] 9d c4 [2] 92 de [2] 8c c3 [2] 8e c2 [2] 95 c4 [2] 89 c3 [2] 95 ec }

  condition:
    any of them
}