rule TTP_XOR_QUAD_CurrentVersionRun_fbb4 {
  strings:
    $key_fbb4 = { a8 db [2] 8c d5 [2] a7 f9 [2] 89 db [2] 9d c0 [2] 92 da [2] 8c c7 [2] 8e c6 [2] 95 c0 [2] 89 c7 [2] 95 e8 }

  condition:
    any of them
}