rule TTP_XOR_QUAD_CurrentVersionRun_10bc {
  strings:
    $key_10bc = { 43 d3 [2] 67 dd [2] 4c f1 [2] 62 d3 [2] 76 c8 [2] 79 d2 [2] 67 cf [2] 65 ce [2] 7e c8 [2] 62 cf [2] 7e e0 }

  condition:
    any of them
}