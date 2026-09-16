rule TTP_XOR_QUAD_CurrentVersionRun_e881 {
  strings:
    $key_e881 = { bb ee [2] 9f e0 [2] b4 cc [2] 9a ee [2] 8e f5 [2] 81 ef [2] 9f f2 [2] 9d f3 [2] 86 f5 [2] 9a f2 [2] 86 dd }

  condition:
    any of them
}