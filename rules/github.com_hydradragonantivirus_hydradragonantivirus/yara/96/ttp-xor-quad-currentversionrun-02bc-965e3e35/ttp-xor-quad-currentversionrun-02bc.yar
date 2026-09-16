rule TTP_XOR_QUAD_CurrentVersionRun_02bc {
  strings:
    $key_02bc = { 51 d3 [2] 75 dd [2] 5e f1 [2] 70 d3 [2] 64 c8 [2] 6b d2 [2] 75 cf [2] 77 ce [2] 6c c8 [2] 70 cf [2] 6c e0 }

  condition:
    any of them
}