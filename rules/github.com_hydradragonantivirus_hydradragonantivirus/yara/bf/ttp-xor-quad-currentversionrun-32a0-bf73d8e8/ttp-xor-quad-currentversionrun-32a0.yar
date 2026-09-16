rule TTP_XOR_QUAD_CurrentVersionRun_32a0 {
  strings:
    $key_32a0 = { 61 cf [2] 45 c1 [2] 6e ed [2] 40 cf [2] 54 d4 [2] 5b ce [2] 45 d3 [2] 47 d2 [2] 5c d4 [2] 40 d3 [2] 5c fc }

  condition:
    any of them
}