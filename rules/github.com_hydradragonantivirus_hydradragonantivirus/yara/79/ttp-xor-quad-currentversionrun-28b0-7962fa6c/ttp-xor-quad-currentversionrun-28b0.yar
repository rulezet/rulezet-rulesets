rule TTP_XOR_QUAD_CurrentVersionRun_28b0 {
  strings:
    $key_28b0 = { 7b df [2] 5f d1 [2] 74 fd [2] 5a df [2] 4e c4 [2] 41 de [2] 5f c3 [2] 5d c2 [2] 46 c4 [2] 5a c3 [2] 46 ec }

  condition:
    any of them
}