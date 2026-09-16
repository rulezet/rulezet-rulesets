rule TTP_XOR_QUAD_CurrentVersionRun_a1ae {
  strings:
    $key_a1ae = { f2 c1 [2] d6 cf [2] fd e3 [2] d3 c1 [2] c7 da [2] c8 c0 [2] d6 dd [2] d4 dc [2] cf da [2] d3 dd [2] cf f2 }

  condition:
    any of them
}