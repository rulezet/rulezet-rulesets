rule TTP_XOR_QUAD_CurrentVersionRun_a681 {
  strings:
    $key_a681 = { f5 ee [2] d1 e0 [2] fa cc [2] d4 ee [2] c0 f5 [2] cf ef [2] d1 f2 [2] d3 f3 [2] c8 f5 [2] d4 f2 [2] c8 dd }

  condition:
    any of them
}