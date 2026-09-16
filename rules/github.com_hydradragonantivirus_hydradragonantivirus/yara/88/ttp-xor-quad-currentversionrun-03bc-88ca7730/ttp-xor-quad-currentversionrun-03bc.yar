rule TTP_XOR_QUAD_CurrentVersionRun_03bc {
  strings:
    $key_03bc = { 50 d3 [2] 74 dd [2] 5f f1 [2] 71 d3 [2] 65 c8 [2] 6a d2 [2] 74 cf [2] 76 ce [2] 6d c8 [2] 71 cf [2] 6d e0 }

  condition:
    any of them
}