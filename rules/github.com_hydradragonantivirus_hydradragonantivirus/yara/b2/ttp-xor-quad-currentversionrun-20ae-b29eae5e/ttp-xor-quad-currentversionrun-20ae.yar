rule TTP_XOR_QUAD_CurrentVersionRun_20ae {
  strings:
    $key_20ae = { 73 c1 [2] 57 cf [2] 7c e3 [2] 52 c1 [2] 46 da [2] 49 c0 [2] 57 dd [2] 55 dc [2] 4e da [2] 52 dd [2] 4e f2 }

  condition:
    any of them
}