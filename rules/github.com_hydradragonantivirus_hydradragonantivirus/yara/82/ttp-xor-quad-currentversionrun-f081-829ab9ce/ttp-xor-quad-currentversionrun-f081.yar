rule TTP_XOR_QUAD_CurrentVersionRun_f081 {
  strings:
    $key_f081 = { a3 ee [2] 87 e0 [2] ac cc [2] 82 ee [2] 96 f5 [2] 99 ef [2] 87 f2 [2] 85 f3 [2] 9e f5 [2] 82 f2 [2] 9e dd }

  condition:
    any of them
}