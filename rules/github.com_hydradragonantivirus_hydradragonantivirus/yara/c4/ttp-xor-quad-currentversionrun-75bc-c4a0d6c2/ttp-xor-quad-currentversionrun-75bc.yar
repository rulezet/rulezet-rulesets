rule TTP_XOR_QUAD_CurrentVersionRun_75bc {
  strings:
    $key_75bc = { 26 d3 [2] 02 dd [2] 29 f1 [2] 07 d3 [2] 13 c8 [2] 1c d2 [2] 02 cf [2] 00 ce [2] 1b c8 [2] 07 cf [2] 1b e0 }

  condition:
    any of them
}