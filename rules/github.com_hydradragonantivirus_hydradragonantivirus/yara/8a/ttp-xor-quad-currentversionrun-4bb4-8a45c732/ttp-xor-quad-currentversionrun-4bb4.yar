rule TTP_XOR_QUAD_CurrentVersionRun_4bb4 {
  strings:
    $key_4bb4 = { 18 db [2] 3c d5 [2] 17 f9 [2] 39 db [2] 2d c0 [2] 22 da [2] 3c c7 [2] 3e c6 [2] 25 c0 [2] 39 c7 [2] 25 e8 }

  condition:
    any of them
}