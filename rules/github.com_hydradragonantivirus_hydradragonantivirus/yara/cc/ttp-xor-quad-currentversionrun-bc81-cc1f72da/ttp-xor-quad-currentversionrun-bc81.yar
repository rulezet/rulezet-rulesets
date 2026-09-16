rule TTP_XOR_QUAD_CurrentVersionRun_bc81 {
  strings:
    $key_bc81 = { ef ee [2] cb e0 [2] e0 cc [2] ce ee [2] da f5 [2] d5 ef [2] cb f2 [2] c9 f3 [2] d2 f5 [2] ce f2 [2] d2 dd }

  condition:
    any of them
}