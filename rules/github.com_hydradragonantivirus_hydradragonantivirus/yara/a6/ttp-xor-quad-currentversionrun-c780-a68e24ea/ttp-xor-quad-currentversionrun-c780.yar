rule TTP_XOR_QUAD_CurrentVersionRun_c780 {
  strings:
    $key_c780 = { 94 ef [2] b0 e1 [2] 9b cd [2] b5 ef [2] a1 f4 [2] ae ee [2] b0 f3 [2] b2 f2 [2] a9 f4 [2] b5 f3 [2] a9 dc }

  condition:
    any of them
}