rule TTP_XOR_QUAD_CurrentVersionRun_b4ae {
  strings:
    $key_b4ae = { e7 c1 [2] c3 cf [2] e8 e3 [2] c6 c1 [2] d2 da [2] dd c0 [2] c3 dd [2] c1 dc [2] da da [2] c6 dd [2] da f2 }

  condition:
    any of them
}