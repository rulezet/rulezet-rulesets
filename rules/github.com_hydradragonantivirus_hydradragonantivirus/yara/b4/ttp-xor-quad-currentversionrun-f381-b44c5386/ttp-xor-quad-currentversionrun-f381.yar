rule TTP_XOR_QUAD_CurrentVersionRun_f381 {
  strings:
    $key_f381 = { a0 ee [2] 84 e0 [2] af cc [2] 81 ee [2] 95 f5 [2] 9a ef [2] 84 f2 [2] 86 f3 [2] 9d f5 [2] 81 f2 [2] 9d dd }

  condition:
    any of them
}