rule TTP_XOR_QUAD_CurrentVersionRun_a497 {
  strings:
    $key_a497 = { f7 f8 [2] d3 f6 [2] f8 da [2] d6 f8 [2] c2 e3 [2] cd f9 [2] d3 e4 [2] d1 e5 [2] ca e3 [2] d6 e4 [2] ca cb }

  condition:
    any of them
}