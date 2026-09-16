rule TTP_XOR_QUAD_CurrentVersionRun_7a81 {
  strings:
    $key_7a81 = { 29 ee [2] 0d e0 [2] 26 cc [2] 08 ee [2] 1c f5 [2] 13 ef [2] 0d f2 [2] 0f f3 [2] 14 f5 [2] 08 f2 [2] 14 dd }

  condition:
    any of them
}