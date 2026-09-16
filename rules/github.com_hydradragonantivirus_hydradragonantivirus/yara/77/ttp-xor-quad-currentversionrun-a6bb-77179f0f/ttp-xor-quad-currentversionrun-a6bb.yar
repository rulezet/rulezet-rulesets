rule TTP_XOR_QUAD_CurrentVersionRun_a6bb {
  strings:
    $key_a6bb = { f5 d4 [2] d1 da [2] fa f6 [2] d4 d4 [2] c0 cf [2] cf d5 [2] d1 c8 [2] d3 c9 [2] c8 cf [2] d4 c8 [2] c8 e7 }

  condition:
    any of them
}