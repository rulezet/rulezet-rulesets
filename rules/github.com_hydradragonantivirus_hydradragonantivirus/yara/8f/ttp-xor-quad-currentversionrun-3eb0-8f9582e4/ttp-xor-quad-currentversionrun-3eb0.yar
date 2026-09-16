rule TTP_XOR_QUAD_CurrentVersionRun_3eb0 {
  strings:
    $key_3eb0 = { 6d df [2] 49 d1 [2] 62 fd [2] 4c df [2] 58 c4 [2] 57 de [2] 49 c3 [2] 4b c2 [2] 50 c4 [2] 4c c3 [2] 50 ec }

  condition:
    any of them
}