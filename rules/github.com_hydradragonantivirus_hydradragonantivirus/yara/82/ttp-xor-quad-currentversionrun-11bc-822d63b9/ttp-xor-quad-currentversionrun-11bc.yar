rule TTP_XOR_QUAD_CurrentVersionRun_11bc {
  strings:
    $key_11bc = { 42 d3 [2] 66 dd [2] 4d f1 [2] 63 d3 [2] 77 c8 [2] 78 d2 [2] 66 cf [2] 64 ce [2] 7f c8 [2] 63 cf [2] 7f e0 }

  condition:
    any of them
}