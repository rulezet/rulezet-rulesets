rule TTP_XOR_QUAD_CurrentVersionRun_b381 {
  strings:
    $key_b381 = { e0 ee [2] c4 e0 [2] ef cc [2] c1 ee [2] d5 f5 [2] da ef [2] c4 f2 [2] c6 f3 [2] dd f5 [2] c1 f2 [2] dd dd }

  condition:
    any of them
}