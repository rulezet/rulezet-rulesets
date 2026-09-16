rule TTP_XOR_QUAD_CurrentVersionRun_b0bb {
  strings:
    $key_b0bb = { e3 d4 [2] c7 da [2] ec f6 [2] c2 d4 [2] d6 cf [2] d9 d5 [2] c7 c8 [2] c5 c9 [2] de cf [2] c2 c8 [2] de e7 }

  condition:
    any of them
}