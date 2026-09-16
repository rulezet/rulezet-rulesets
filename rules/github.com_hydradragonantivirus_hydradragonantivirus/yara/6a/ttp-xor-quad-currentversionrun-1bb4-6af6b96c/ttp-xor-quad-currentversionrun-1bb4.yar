rule TTP_XOR_QUAD_CurrentVersionRun_1bb4 {
  strings:
    $key_1bb4 = { 48 db [2] 6c d5 [2] 47 f9 [2] 69 db [2] 7d c0 [2] 72 da [2] 6c c7 [2] 6e c6 [2] 75 c0 [2] 69 c7 [2] 75 e8 }

  condition:
    any of them
}