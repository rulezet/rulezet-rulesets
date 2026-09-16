rule TTP_XOR_QUAD_CurrentVersionRun_45bc {
  strings:
    $key_45bc = { 16 d3 [2] 32 dd [2] 19 f1 [2] 37 d3 [2] 23 c8 [2] 2c d2 [2] 32 cf [2] 30 ce [2] 2b c8 [2] 37 cf [2] 2b e0 }

  condition:
    any of them
}