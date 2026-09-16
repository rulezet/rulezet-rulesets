rule TTP_XOR_QUAD_CurrentVersionRun_69b0 {
  strings:
    $key_69b0 = { 3a df [2] 1e d1 [2] 35 fd [2] 1b df [2] 0f c4 [2] 00 de [2] 1e c3 [2] 1c c2 [2] 07 c4 [2] 1b c3 [2] 07 ec }

  condition:
    any of them
}