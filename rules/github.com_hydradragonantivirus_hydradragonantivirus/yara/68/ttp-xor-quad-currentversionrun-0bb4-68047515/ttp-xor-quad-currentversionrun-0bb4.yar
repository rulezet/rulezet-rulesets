rule TTP_XOR_QUAD_CurrentVersionRun_0bb4 {
  strings:
    $key_0bb4 = { 58 db [2] 7c d5 [2] 57 f9 [2] 79 db [2] 6d c0 [2] 62 da [2] 7c c7 [2] 7e c6 [2] 65 c0 [2] 79 c7 [2] 65 e8 }

  condition:
    any of them
}