rule TTP_XOR_QUAD_CurrentVersionRun_71ae {
  strings:
    $key_71ae = { 22 c1 [2] 06 cf [2] 2d e3 [2] 03 c1 [2] 17 da [2] 18 c0 [2] 06 dd [2] 04 dc [2] 1f da [2] 03 dd [2] 1f f2 }

  condition:
    any of them
}