rule TTP_XOR_QUAD_CurrentVersionRun_31ae {
  strings:
    $key_31ae = { 62 c1 [2] 46 cf [2] 6d e3 [2] 43 c1 [2] 57 da [2] 58 c0 [2] 46 dd [2] 44 dc [2] 5f da [2] 43 dd [2] 5f f2 }

  condition:
    any of them
}