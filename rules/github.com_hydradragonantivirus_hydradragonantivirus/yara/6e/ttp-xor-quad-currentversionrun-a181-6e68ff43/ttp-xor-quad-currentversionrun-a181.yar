rule TTP_XOR_QUAD_CurrentVersionRun_a181 {
  strings:
    $key_a181 = { f2 ee [2] d6 e0 [2] fd cc [2] d3 ee [2] c7 f5 [2] c8 ef [2] d6 f2 [2] d4 f3 [2] cf f5 [2] d3 f2 [2] cf dd }

  condition:
    any of them
}