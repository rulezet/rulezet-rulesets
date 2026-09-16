rule TTP_XOR_QUAD_CurrentVersionRun_a981 {
  strings:
    $key_a981 = { fa ee [2] de e0 [2] f5 cc [2] db ee [2] cf f5 [2] c0 ef [2] de f2 [2] dc f3 [2] c7 f5 [2] db f2 [2] c7 dd }

  condition:
    any of them
}