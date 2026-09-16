rule TTP_XOR_QUAD_CurrentVersionRun_54bc {
  strings:
    $key_54bc = { 07 d3 [2] 23 dd [2] 08 f1 [2] 26 d3 [2] 32 c8 [2] 3d d2 [2] 23 cf [2] 21 ce [2] 3a c8 [2] 26 cf [2] 3a e0 }

  condition:
    any of them
}