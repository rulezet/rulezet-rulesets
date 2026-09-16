rule TTP_XOR_QUAD_CurrentVersionRun_1381 {
  strings:
    $key_1381 = { 40 ee [2] 64 e0 [2] 4f cc [2] 61 ee [2] 75 f5 [2] 7a ef [2] 64 f2 [2] 66 f3 [2] 7d f5 [2] 61 f2 [2] 7d dd }

  condition:
    any of them
}