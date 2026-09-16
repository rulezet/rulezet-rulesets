rule TTP_XOR_QUAD_CurrentVersionRun_f0b5 {
  strings:
    $key_f0b5 = { a3 da [2] 87 d4 [2] ac f8 [2] 82 da [2] 96 c1 [2] 99 db [2] 87 c6 [2] 85 c7 [2] 9e c1 [2] 82 c6 [2] 9e e9 }

  condition:
    any of them
}