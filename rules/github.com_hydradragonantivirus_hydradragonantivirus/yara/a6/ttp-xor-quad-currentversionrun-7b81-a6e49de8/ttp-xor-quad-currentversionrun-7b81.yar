rule TTP_XOR_QUAD_CurrentVersionRun_7b81 {
  strings:
    $key_7b81 = { 28 ee [2] 0c e0 [2] 27 cc [2] 09 ee [2] 1d f5 [2] 12 ef [2] 0c f2 [2] 0e f3 [2] 15 f5 [2] 09 f2 [2] 15 dd }

  condition:
    any of them
}