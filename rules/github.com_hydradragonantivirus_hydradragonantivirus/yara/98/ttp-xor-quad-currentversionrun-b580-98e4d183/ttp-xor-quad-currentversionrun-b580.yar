rule TTP_XOR_QUAD_CurrentVersionRun_b580 {
  strings:
    $key_b580 = { e6 ef [2] c2 e1 [2] e9 cd [2] c7 ef [2] d3 f4 [2] dc ee [2] c2 f3 [2] c0 f2 [2] db f4 [2] c7 f3 [2] db dc }

  condition:
    any of them
}