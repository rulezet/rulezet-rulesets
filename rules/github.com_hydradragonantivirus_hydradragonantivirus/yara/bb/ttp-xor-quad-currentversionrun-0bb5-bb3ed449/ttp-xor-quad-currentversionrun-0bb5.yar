rule TTP_XOR_QUAD_CurrentVersionRun_0bb5 {
  strings:
    $key_0bb5 = { 58 da [2] 7c d4 [2] 57 f8 [2] 79 da [2] 6d c1 [2] 62 db [2] 7c c6 [2] 7e c7 [2] 65 c1 [2] 79 c6 [2] 65 e9 }

  condition:
    any of them
}