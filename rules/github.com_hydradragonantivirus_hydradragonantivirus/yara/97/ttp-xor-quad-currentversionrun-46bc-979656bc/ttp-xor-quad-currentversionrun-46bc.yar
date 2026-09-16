rule TTP_XOR_QUAD_CurrentVersionRun_46bc {
  strings:
    $key_46bc = { 15 d3 [2] 31 dd [2] 1a f1 [2] 34 d3 [2] 20 c8 [2] 2f d2 [2] 31 cf [2] 33 ce [2] 28 c8 [2] 34 cf [2] 28 e0 }

  condition:
    any of them
}