rule TTP_XOR_QUAD_CurrentVersionRun_41bc {
  strings:
    $key_41bc = { 12 d3 [2] 36 dd [2] 1d f1 [2] 33 d3 [2] 27 c8 [2] 28 d2 [2] 36 cf [2] 34 ce [2] 2f c8 [2] 33 cf [2] 2f e0 }

  condition:
    any of them
}