rule TTP_XOR_QUAD_CurrentVersionRun_67ae {
  strings:
    $key_67ae = { 34 c1 [2] 10 cf [2] 3b e3 [2] 15 c1 [2] 01 da [2] 0e c0 [2] 10 dd [2] 12 dc [2] 09 da [2] 15 dd [2] 09 f2 }

  condition:
    any of them
}