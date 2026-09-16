rule TTP_XOR_QUAD_CurrentVersionRun_73bc {
  strings:
    $key_73bc = { 20 d3 [2] 04 dd [2] 2f f1 [2] 01 d3 [2] 15 c8 [2] 1a d2 [2] 04 cf [2] 06 ce [2] 1d c8 [2] 01 cf [2] 1d e0 }

  condition:
    any of them
}