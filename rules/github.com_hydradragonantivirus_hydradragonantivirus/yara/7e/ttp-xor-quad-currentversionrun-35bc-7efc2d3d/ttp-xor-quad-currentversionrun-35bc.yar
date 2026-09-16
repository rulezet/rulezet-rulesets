rule TTP_XOR_QUAD_CurrentVersionRun_35bc {
  strings:
    $key_35bc = { 66 d3 [2] 42 dd [2] 69 f1 [2] 47 d3 [2] 53 c8 [2] 5c d2 [2] 42 cf [2] 40 ce [2] 5b c8 [2] 47 cf [2] 5b e0 }

  condition:
    any of them
}