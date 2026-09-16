rule TTP_XOR_QUAD_CurrentVersionRun_39b4 {
  strings:
    $key_39b4 = { 6a db [2] 4e d5 [2] 65 f9 [2] 4b db [2] 5f c0 [2] 50 da [2] 4e c7 [2] 4c c6 [2] 57 c0 [2] 4b c7 [2] 57 e8 }

  condition:
    any of them
}