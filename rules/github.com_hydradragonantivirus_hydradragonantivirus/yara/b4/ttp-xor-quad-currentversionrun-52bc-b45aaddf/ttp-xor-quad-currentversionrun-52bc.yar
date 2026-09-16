rule TTP_XOR_QUAD_CurrentVersionRun_52bc {
  strings:
    $key_52bc = { 01 d3 [2] 25 dd [2] 0e f1 [2] 20 d3 [2] 34 c8 [2] 3b d2 [2] 25 cf [2] 27 ce [2] 3c c8 [2] 20 cf [2] 3c e0 }

  condition:
    any of them
}