rule TTP_XOR_QUAD_CurrentVersionRun_49b4 {
  strings:
    $key_49b4 = { 1a db [2] 3e d5 [2] 15 f9 [2] 3b db [2] 2f c0 [2] 20 da [2] 3e c7 [2] 3c c6 [2] 27 c0 [2] 3b c7 [2] 27 e8 }

  condition:
    any of them
}