rule TTP_XOR_QUAD_CurrentVersionRun_0881 {
  strings:
    $key_0881 = { 5b ee [2] 7f e0 [2] 54 cc [2] 7a ee [2] 6e f5 [2] 61 ef [2] 7f f2 [2] 7d f3 [2] 66 f5 [2] 7a f2 [2] 66 dd }

  condition:
    any of them
}