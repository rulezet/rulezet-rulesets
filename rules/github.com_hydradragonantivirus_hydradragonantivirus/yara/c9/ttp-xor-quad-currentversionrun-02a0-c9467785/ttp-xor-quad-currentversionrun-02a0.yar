rule TTP_XOR_QUAD_CurrentVersionRun_02a0 {
  strings:
    $key_02a0 = { 51 cf [2] 75 c1 [2] 5e ed [2] 70 cf [2] 64 d4 [2] 6b ce [2] 75 d3 [2] 77 d2 [2] 6c d4 [2] 70 d3 [2] 6c fc }

  condition:
    any of them
}