rule TTP_XOR_QUAD_CurrentVersionRun_b781 {
  strings:
    $key_b781 = { e4 ee [2] c0 e0 [2] eb cc [2] c5 ee [2] d1 f5 [2] de ef [2] c0 f2 [2] c2 f3 [2] d9 f5 [2] c5 f2 [2] d9 dd }

  condition:
    any of them
}