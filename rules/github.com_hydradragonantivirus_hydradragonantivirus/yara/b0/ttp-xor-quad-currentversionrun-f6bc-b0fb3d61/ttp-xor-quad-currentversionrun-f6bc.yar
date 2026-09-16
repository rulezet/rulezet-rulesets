rule TTP_XOR_QUAD_CurrentVersionRun_f6bc {
  strings:
    $key_f6bc = { a5 d3 [2] 81 dd [2] aa f1 [2] 84 d3 [2] 90 c8 [2] 9f d2 [2] 81 cf [2] 83 ce [2] 98 c8 [2] 84 cf [2] 98 e0 }

  condition:
    any of them
}