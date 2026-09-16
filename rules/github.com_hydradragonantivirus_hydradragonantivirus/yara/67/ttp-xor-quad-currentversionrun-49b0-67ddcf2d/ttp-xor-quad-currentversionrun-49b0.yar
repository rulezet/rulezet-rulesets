rule TTP_XOR_QUAD_CurrentVersionRun_49b0 {
  strings:
    $key_49b0 = { 1a df [2] 3e d1 [2] 15 fd [2] 3b df [2] 2f c4 [2] 20 de [2] 3e c3 [2] 3c c2 [2] 27 c4 [2] 3b c3 [2] 27 ec }

  condition:
    any of them
}