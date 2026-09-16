rule TTP_XOR_QUAD_CurrentVersionRun_a680 {
  strings:
    $key_a680 = { f5 ef [2] d1 e1 [2] fa cd [2] d4 ef [2] c0 f4 [2] cf ee [2] d1 f3 [2] d3 f2 [2] c8 f4 [2] d4 f3 [2] c8 dc }

  condition:
    any of them
}