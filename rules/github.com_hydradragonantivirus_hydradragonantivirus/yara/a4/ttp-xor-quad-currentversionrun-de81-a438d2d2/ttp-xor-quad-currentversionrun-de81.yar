rule TTP_XOR_QUAD_CurrentVersionRun_de81 {
  strings:
    $key_de81 = { 8d ee [2] a9 e0 [2] 82 cc [2] ac ee [2] b8 f5 [2] b7 ef [2] a9 f2 [2] ab f3 [2] b0 f5 [2] ac f2 [2] b0 dd }

  condition:
    any of them
}