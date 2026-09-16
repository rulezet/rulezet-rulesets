rule TTP_XOR_QUAD_CurrentVersionRun_1881 {
  strings:
    $key_1881 = { 4b ee [2] 6f e0 [2] 44 cc [2] 6a ee [2] 7e f5 [2] 71 ef [2] 6f f2 [2] 6d f3 [2] 76 f5 [2] 6a f2 [2] 76 dd }

  condition:
    any of them
}