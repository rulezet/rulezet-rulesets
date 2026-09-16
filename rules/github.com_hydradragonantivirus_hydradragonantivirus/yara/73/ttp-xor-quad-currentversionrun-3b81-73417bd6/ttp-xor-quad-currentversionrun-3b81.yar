rule TTP_XOR_QUAD_CurrentVersionRun_3b81 {
  strings:
    $key_3b81 = { 68 ee [2] 4c e0 [2] 67 cc [2] 49 ee [2] 5d f5 [2] 52 ef [2] 4c f2 [2] 4e f3 [2] 55 f5 [2] 49 f2 [2] 55 dd }

  condition:
    any of them
}