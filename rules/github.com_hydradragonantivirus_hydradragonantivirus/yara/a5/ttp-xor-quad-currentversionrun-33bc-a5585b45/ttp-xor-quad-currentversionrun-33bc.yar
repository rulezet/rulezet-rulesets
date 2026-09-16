rule TTP_XOR_QUAD_CurrentVersionRun_33bc {
  strings:
    $key_33bc = { 60 d3 [2] 44 dd [2] 6f f1 [2] 41 d3 [2] 55 c8 [2] 5a d2 [2] 44 cf [2] 46 ce [2] 5d c8 [2] 41 cf [2] 5d e0 }

  condition:
    any of them
}