rule TTP_XOR_QUAD_CurrentVersionRun_b7ae {
  strings:
    $key_b7ae = { e4 c1 [2] c0 cf [2] eb e3 [2] c5 c1 [2] d1 da [2] de c0 [2] c0 dd [2] c2 dc [2] d9 da [2] c5 dd [2] d9 f2 }

  condition:
    any of them
}