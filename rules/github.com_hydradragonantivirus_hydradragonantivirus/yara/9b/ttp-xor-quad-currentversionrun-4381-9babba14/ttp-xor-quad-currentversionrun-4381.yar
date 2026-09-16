rule TTP_XOR_QUAD_CurrentVersionRun_4381 {
  strings:
    $key_4381 = { 10 ee [2] 34 e0 [2] 1f cc [2] 31 ee [2] 25 f5 [2] 2a ef [2] 34 f2 [2] 36 f3 [2] 2d f5 [2] 31 f2 [2] 2d dd }

  condition:
    any of them
}