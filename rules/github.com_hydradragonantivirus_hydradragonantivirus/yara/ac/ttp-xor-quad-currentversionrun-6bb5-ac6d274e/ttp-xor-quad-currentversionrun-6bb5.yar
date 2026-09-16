rule TTP_XOR_QUAD_CurrentVersionRun_6bb5 {
  strings:
    $key_6bb5 = { 38 da [2] 1c d4 [2] 37 f8 [2] 19 da [2] 0d c1 [2] 02 db [2] 1c c6 [2] 1e c7 [2] 05 c1 [2] 19 c6 [2] 05 e9 }

  condition:
    any of them
}