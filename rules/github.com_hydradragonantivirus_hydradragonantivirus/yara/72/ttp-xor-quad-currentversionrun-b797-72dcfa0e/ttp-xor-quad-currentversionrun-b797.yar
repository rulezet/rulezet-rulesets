rule TTP_XOR_QUAD_CurrentVersionRun_b797 {
  strings:
    $key_b797 = { e4 f8 [2] c0 f6 [2] eb da [2] c5 f8 [2] d1 e3 [2] de f9 [2] c0 e4 [2] c2 e5 [2] d9 e3 [2] c5 e4 [2] d9 cb }

  condition:
    any of them
}