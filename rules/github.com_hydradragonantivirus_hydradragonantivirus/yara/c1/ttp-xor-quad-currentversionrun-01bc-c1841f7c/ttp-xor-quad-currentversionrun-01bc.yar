rule TTP_XOR_QUAD_CurrentVersionRun_01bc {
  strings:
    $key_01bc = { 52 d3 [2] 76 dd [2] 5d f1 [2] 73 d3 [2] 67 c8 [2] 68 d2 [2] 76 cf [2] 74 ce [2] 6f c8 [2] 73 cf [2] 6f e0 }

  condition:
    any of them
}