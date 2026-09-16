rule TTP_XOR_QUAD_CurrentVersionRun_71bc {
  strings:
    $key_71bc = { 22 d3 [2] 06 dd [2] 2d f1 [2] 03 d3 [2] 17 c8 [2] 18 d2 [2] 06 cf [2] 04 ce [2] 1f c8 [2] 03 cf [2] 1f e0 }

  condition:
    any of them
}