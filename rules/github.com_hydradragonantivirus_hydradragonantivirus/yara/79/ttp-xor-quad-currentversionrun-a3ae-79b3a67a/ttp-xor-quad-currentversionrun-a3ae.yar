rule TTP_XOR_QUAD_CurrentVersionRun_a3ae {
  strings:
    $key_a3ae = { f0 c1 [2] d4 cf [2] ff e3 [2] d1 c1 [2] c5 da [2] ca c0 [2] d4 dd [2] d6 dc [2] cd da [2] d1 dd [2] cd f2 }

  condition:
    any of them
}