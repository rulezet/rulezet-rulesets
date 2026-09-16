rule TTP_XOR_QUAD_CurrentVersionRun_5881 {
  strings:
    $key_5881 = { 0b ee [2] 2f e0 [2] 04 cc [2] 2a ee [2] 3e f5 [2] 31 ef [2] 2f f2 [2] 2d f3 [2] 36 f5 [2] 2a f2 [2] 36 dd }

  condition:
    any of them
}