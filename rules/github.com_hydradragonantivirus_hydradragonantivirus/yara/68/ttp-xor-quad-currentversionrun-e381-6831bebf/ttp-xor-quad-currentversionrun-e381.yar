rule TTP_XOR_QUAD_CurrentVersionRun_e381 {
  strings:
    $key_e381 = { b0 ee [2] 94 e0 [2] bf cc [2] 91 ee [2] 85 f5 [2] 8a ef [2] 94 f2 [2] 96 f3 [2] 8d f5 [2] 91 f2 [2] 8d dd }

  condition:
    any of them
}