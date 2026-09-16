rule TTP_XOR_QUAD_CurrentVersionRun_60bc {
  strings:
    $key_60bc = { 33 d3 [2] 17 dd [2] 3c f1 [2] 12 d3 [2] 06 c8 [2] 09 d2 [2] 17 cf [2] 15 ce [2] 0e c8 [2] 12 cf [2] 0e e0 }

  condition:
    any of them
}