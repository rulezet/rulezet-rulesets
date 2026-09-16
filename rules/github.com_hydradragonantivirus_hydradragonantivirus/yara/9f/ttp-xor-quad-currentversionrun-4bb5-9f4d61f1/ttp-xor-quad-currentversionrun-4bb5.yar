rule TTP_XOR_QUAD_CurrentVersionRun_4bb5 {
  strings:
    $key_4bb5 = { 18 da [2] 3c d4 [2] 17 f8 [2] 39 da [2] 2d c1 [2] 22 db [2] 3c c6 [2] 3e c7 [2] 25 c1 [2] 39 c6 [2] 25 e9 }

  condition:
    any of them
}