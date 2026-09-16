rule TTP_XOR_QUAD_CurrentVersionRun_6bb4 {
  strings:
    $key_6bb4 = { 38 db [2] 1c d5 [2] 37 f9 [2] 19 db [2] 0d c0 [2] 02 da [2] 1c c7 [2] 1e c6 [2] 05 c0 [2] 19 c7 [2] 05 e8 }

  condition:
    any of them
}