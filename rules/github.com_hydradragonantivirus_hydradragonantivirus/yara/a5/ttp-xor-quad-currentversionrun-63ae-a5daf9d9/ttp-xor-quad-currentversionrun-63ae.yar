rule TTP_XOR_QUAD_CurrentVersionRun_63ae {
  strings:
    $key_63ae = { 30 c1 [2] 14 cf [2] 3f e3 [2] 11 c1 [2] 05 da [2] 0a c0 [2] 14 dd [2] 16 dc [2] 0d da [2] 11 dd [2] 0d f2 }

  condition:
    any of them
}