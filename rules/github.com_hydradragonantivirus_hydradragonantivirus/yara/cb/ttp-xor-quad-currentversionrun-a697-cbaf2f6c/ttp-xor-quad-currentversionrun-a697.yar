rule TTP_XOR_QUAD_CurrentVersionRun_a697 {
  strings:
    $key_a697 = { f5 f8 [2] d1 f6 [2] fa da [2] d4 f8 [2] c0 e3 [2] cf f9 [2] d1 e4 [2] d3 e5 [2] c8 e3 [2] d4 e4 [2] c8 cb }

  condition:
    any of them
}