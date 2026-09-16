rule TTP_XOR_QUAD_CurrentVersionRun_b780 {
  strings:
    $key_b780 = { e4 ef [2] c0 e1 [2] eb cd [2] c5 ef [2] d1 f4 [2] de ee [2] c0 f3 [2] c2 f2 [2] d9 f4 [2] c5 f3 [2] d9 dc }

  condition:
    any of them
}