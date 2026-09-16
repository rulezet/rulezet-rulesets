rule TTP_XOR_QUAD_CurrentVersionRun_3381 {
  strings:
    $key_3381 = { 60 ee [2] 44 e0 [2] 6f cc [2] 41 ee [2] 55 f5 [2] 5a ef [2] 44 f2 [2] 46 f3 [2] 5d f5 [2] 41 f2 [2] 5d dd }

  condition:
    any of them
}