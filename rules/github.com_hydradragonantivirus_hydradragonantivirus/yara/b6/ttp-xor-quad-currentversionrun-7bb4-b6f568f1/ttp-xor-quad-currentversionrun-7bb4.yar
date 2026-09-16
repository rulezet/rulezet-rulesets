rule TTP_XOR_QUAD_CurrentVersionRun_7bb4 {
  strings:
    $key_7bb4 = { 28 db [2] 0c d5 [2] 27 f9 [2] 09 db [2] 1d c0 [2] 12 da [2] 0c c7 [2] 0e c6 [2] 15 c0 [2] 09 c7 [2] 15 e8 }

  condition:
    any of them
}