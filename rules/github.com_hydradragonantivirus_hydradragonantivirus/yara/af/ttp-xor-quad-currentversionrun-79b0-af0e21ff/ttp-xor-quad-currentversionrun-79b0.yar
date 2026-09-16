rule TTP_XOR_QUAD_CurrentVersionRun_79b0 {
  strings:
    $key_79b0 = { 2a df [2] 0e d1 [2] 25 fd [2] 0b df [2] 1f c4 [2] 10 de [2] 0e c3 [2] 0c c2 [2] 17 c4 [2] 0b c3 [2] 17 ec }

  condition:
    any of them
}