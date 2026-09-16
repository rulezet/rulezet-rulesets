rule TTP_XOR_QUAD_CurrentVersionRun_6a81 {
  strings:
    $key_6a81 = { 39 ee [2] 1d e0 [2] 36 cc [2] 18 ee [2] 0c f5 [2] 03 ef [2] 1d f2 [2] 1f f3 [2] 04 f5 [2] 18 f2 [2] 04 dd }

  condition:
    any of them
}