rule TTP_XOR_QUAD_CurrentVersionRun_7381 {
  strings:
    $key_7381 = { 20 ee [2] 04 e0 [2] 2f cc [2] 01 ee [2] 15 f5 [2] 1a ef [2] 04 f2 [2] 06 f3 [2] 1d f5 [2] 01 f2 [2] 1d dd }

  condition:
    any of them
}