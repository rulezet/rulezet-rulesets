rule TTP_XOR_QUAD_CurrentVersionRun_a6ae {
  strings:
    $key_a6ae = { f5 c1 [2] d1 cf [2] fa e3 [2] d4 c1 [2] c0 da [2] cf c0 [2] d1 dd [2] d3 dc [2] c8 da [2] d4 dd [2] c8 f2 }

  condition:
    any of them
}