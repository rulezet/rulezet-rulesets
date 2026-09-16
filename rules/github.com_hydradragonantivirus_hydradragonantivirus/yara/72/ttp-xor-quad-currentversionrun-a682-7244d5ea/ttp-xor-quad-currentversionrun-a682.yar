rule TTP_XOR_QUAD_CurrentVersionRun_a682 {
  strings:
    $key_a682 = { f5 ed [2] d1 e3 [2] fa cf [2] d4 ed [2] c0 f6 [2] cf ec [2] d1 f1 [2] d3 f0 [2] c8 f6 [2] d4 f1 [2] c8 de }

  condition:
    any of them
}