rule TTP_XOR_QUAD_CurrentVersionRun_6381 {
  strings:
    $key_6381 = { 30 ee [2] 14 e0 [2] 3f cc [2] 11 ee [2] 05 f5 [2] 0a ef [2] 14 f2 [2] 16 f3 [2] 0d f5 [2] 11 f2 [2] 0d dd }

  condition:
    any of them
}