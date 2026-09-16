rule TTP_XOR_QUAD_CurrentVersionRun_a0bb {
  strings:
    $key_a0bb = { f3 d4 [2] d7 da [2] fc f6 [2] d2 d4 [2] c6 cf [2] c9 d5 [2] d7 c8 [2] d5 c9 [2] ce cf [2] d2 c8 [2] ce e7 }

  condition:
    any of them
}