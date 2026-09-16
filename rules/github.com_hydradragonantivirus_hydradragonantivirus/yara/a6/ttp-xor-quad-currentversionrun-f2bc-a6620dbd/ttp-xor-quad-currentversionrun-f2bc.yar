rule TTP_XOR_QUAD_CurrentVersionRun_f2bc {
  strings:
    $key_f2bc = { a1 d3 [2] 85 dd [2] ae f1 [2] 80 d3 [2] 94 c8 [2] 9b d2 [2] 85 cf [2] 87 ce [2] 9c c8 [2] 80 cf [2] 9c e0 }

  condition:
    any of them
}