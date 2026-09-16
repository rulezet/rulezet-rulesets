rule TTP_XOR_QUAD_CurrentVersionRun_1eb0 {
  strings:
    $key_1eb0 = { 4d df [2] 69 d1 [2] 42 fd [2] 6c df [2] 78 c4 [2] 77 de [2] 69 c3 [2] 6b c2 [2] 70 c4 [2] 6c c3 [2] 70 ec }

  condition:
    any of them
}