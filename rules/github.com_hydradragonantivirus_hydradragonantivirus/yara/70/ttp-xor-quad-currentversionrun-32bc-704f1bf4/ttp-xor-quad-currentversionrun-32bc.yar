rule TTP_XOR_QUAD_CurrentVersionRun_32bc {
  strings:
    $key_32bc = { 61 d3 [2] 45 dd [2] 6e f1 [2] 40 d3 [2] 54 c8 [2] 5b d2 [2] 45 cf [2] 47 ce [2] 5c c8 [2] 40 cf [2] 5c e0 }

  condition:
    any of them
}