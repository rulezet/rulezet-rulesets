rule TTP_XOR_QUAD_CurrentVersionRun_3a81 {
  strings:
    $key_3a81 = { 69 ee [2] 4d e0 [2] 66 cc [2] 48 ee [2] 5c f5 [2] 53 ef [2] 4d f2 [2] 4f f3 [2] 54 f5 [2] 48 f2 [2] 54 dd }

  condition:
    any of them
}