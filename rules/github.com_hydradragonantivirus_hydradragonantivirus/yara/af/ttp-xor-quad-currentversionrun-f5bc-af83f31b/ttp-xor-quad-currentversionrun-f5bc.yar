rule TTP_XOR_QUAD_CurrentVersionRun_f5bc {
  strings:
    $key_f5bc = { a6 d3 [2] 82 dd [2] a9 f1 [2] 87 d3 [2] 93 c8 [2] 9c d2 [2] 82 cf [2] 80 ce [2] 9b c8 [2] 87 cf [2] 9b e0 }

  condition:
    any of them
}