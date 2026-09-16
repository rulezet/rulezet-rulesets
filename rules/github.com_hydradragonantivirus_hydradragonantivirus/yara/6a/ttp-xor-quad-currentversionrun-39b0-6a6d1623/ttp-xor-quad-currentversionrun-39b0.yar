rule TTP_XOR_QUAD_CurrentVersionRun_39b0 {
  strings:
    $key_39b0 = { 6a df [2] 4e d1 [2] 65 fd [2] 4b df [2] 5f c4 [2] 50 de [2] 4e c3 [2] 4c c2 [2] 57 c4 [2] 4b c3 [2] 57 ec }

  condition:
    any of them
}