rule TTP_XOR_QUAD_CurrentVersionRun_66bc {
  strings:
    $key_66bc = { 35 d3 [2] 11 dd [2] 3a f1 [2] 14 d3 [2] 00 c8 [2] 0f d2 [2] 11 cf [2] 13 ce [2] 08 c8 [2] 14 cf [2] 08 e0 }

  condition:
    any of them
}