rule TTP_XOR_QUAD_CurrentVersionRun_baae {
  strings:
    $key_baae = { e9 c1 [2] cd cf [2] e6 e3 [2] c8 c1 [2] dc da [2] d3 c0 [2] cd dd [2] cf dc [2] d4 da [2] c8 dd [2] d4 f2 }

  condition:
    any of them
}