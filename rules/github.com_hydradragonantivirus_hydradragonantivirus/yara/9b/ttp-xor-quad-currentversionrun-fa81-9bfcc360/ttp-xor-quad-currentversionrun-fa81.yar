rule TTP_XOR_QUAD_CurrentVersionRun_fa81 {
  strings:
    $key_fa81 = { a9 ee [2] 8d e0 [2] a6 cc [2] 88 ee [2] 9c f5 [2] 93 ef [2] 8d f2 [2] 8f f3 [2] 94 f5 [2] 88 f2 [2] 94 dd }

  condition:
    any of them
}