rule TTP_XOR_QUAD_CurrentVersionRun_29b0 {
  strings:
    $key_29b0 = { 7a df [2] 5e d1 [2] 75 fd [2] 5b df [2] 4f c4 [2] 40 de [2] 5e c3 [2] 5c c2 [2] 47 c4 [2] 5b c3 [2] 47 ec }

  condition:
    any of them
}