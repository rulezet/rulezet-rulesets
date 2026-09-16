rule TTP_XOR_QUAD_CurrentVersionRun_7081 {
  strings:
    $key_7081 = { 23 ee [2] 07 e0 [2] 2c cc [2] 02 ee [2] 16 f5 [2] 19 ef [2] 07 f2 [2] 05 f3 [2] 1e f5 [2] 02 f2 [2] 1e dd }

  condition:
    any of them
}