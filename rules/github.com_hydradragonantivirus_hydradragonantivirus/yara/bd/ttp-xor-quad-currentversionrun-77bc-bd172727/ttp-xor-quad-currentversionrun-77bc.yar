rule TTP_XOR_QUAD_CurrentVersionRun_77bc {
  strings:
    $key_77bc = { 24 d3 [2] 00 dd [2] 2b f1 [2] 05 d3 [2] 11 c8 [2] 1e d2 [2] 00 cf [2] 02 ce [2] 19 c8 [2] 05 cf [2] 19 e0 }

  condition:
    any of them
}