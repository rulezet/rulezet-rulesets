rule TTP_XOR_QUAD_CurrentVersionRun_d181 {
  strings:
    $key_d181 = { 82 ee [2] a6 e0 [2] 8d cc [2] a3 ee [2] b7 f5 [2] b8 ef [2] a6 f2 [2] a4 f3 [2] bf f5 [2] a3 f2 [2] bf dd }

  condition:
    any of them
}