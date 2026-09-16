rule TTP_XOR_QUAD_CurrentVersionRun_e9b0 {
  strings:
    $key_e9b0 = { ba df [2] 9e d1 [2] b5 fd [2] 9b df [2] 8f c4 [2] 80 de [2] 9e c3 [2] 9c c2 [2] 87 c4 [2] 9b c3 [2] 87 ec }

  condition:
    any of them
}