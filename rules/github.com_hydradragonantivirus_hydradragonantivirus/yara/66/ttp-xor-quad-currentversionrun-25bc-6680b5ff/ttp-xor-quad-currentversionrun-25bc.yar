rule TTP_XOR_QUAD_CurrentVersionRun_25bc {
  strings:
    $key_25bc = { 76 d3 [2] 52 dd [2] 79 f1 [2] 57 d3 [2] 43 c8 [2] 4c d2 [2] 52 cf [2] 50 ce [2] 4b c8 [2] 57 cf [2] 4b e0 }

  condition:
    any of them
}