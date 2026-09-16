rule TTP_XOR_QUAD_CurrentVersionRun_1a81 {
  strings:
    $key_1a81 = { 49 ee [2] 6d e0 [2] 46 cc [2] 68 ee [2] 7c f5 [2] 73 ef [2] 6d f2 [2] 6f f3 [2] 74 f5 [2] 68 f2 [2] 74 dd }

  condition:
    any of them
}