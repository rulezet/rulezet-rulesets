rule TTP_XOR_QUAD_CurrentVersionRun_e7ae {
  strings:
    $key_e7ae = { b4 c1 [2] 90 cf [2] bb e3 [2] 95 c1 [2] 81 da [2] 8e c0 [2] 90 dd [2] 92 dc [2] 89 da [2] 95 dd [2] 89 f2 }

  condition:
    any of them
}