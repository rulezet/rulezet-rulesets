rule TTP_XOR_QUAD_CurrentVersionRun_a180 {
  strings:
    $key_a180 = { f2 ef [2] d6 e1 [2] fd cd [2] d3 ef [2] c7 f4 [2] c8 ee [2] d6 f3 [2] d4 f2 [2] cf f4 [2] d3 f3 [2] cf dc }

  condition:
    any of them
}