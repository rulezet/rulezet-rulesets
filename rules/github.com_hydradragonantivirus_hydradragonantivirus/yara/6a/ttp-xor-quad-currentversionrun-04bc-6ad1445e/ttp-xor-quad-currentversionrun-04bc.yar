rule TTP_XOR_QUAD_CurrentVersionRun_04bc {
  strings:
    $key_04bc = { 57 d3 [2] 73 dd [2] 58 f1 [2] 76 d3 [2] 62 c8 [2] 6d d2 [2] 73 cf [2] 71 ce [2] 6a c8 [2] 76 cf [2] 6a e0 }

  condition:
    any of them
}