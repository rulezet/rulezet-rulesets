rule TTP_XOR_QUAD_CurrentVersionRun_5b81 {
  strings:
    $key_5b81 = { 08 ee [2] 2c e0 [2] 07 cc [2] 29 ee [2] 3d f5 [2] 32 ef [2] 2c f2 [2] 2e f3 [2] 35 f5 [2] 29 f2 [2] 35 dd }

  condition:
    any of them
}