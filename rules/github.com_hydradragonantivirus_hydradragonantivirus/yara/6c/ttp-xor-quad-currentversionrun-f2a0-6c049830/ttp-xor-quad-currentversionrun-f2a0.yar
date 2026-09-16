rule TTP_XOR_QUAD_CurrentVersionRun_f2a0 {
  strings:
    $key_f2a0 = { a1 cf [2] 85 c1 [2] ae ed [2] 80 cf [2] 94 d4 [2] 9b ce [2] 85 d3 [2] 87 d2 [2] 9c d4 [2] 80 d3 [2] 9c fc }

  condition:
    any of them
}