rule TTP_XOR_QUAD_CurrentVersionRun_3bb5 {
  strings:
    $key_3bb5 = { 68 da [2] 4c d4 [2] 67 f8 [2] 49 da [2] 5d c1 [2] 52 db [2] 4c c6 [2] 4e c7 [2] 55 c1 [2] 49 c6 [2] 55 e9 }

  condition:
    any of them
}