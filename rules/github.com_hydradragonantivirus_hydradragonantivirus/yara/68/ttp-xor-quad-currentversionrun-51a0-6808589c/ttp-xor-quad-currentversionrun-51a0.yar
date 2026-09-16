rule TTP_XOR_QUAD_CurrentVersionRun_51a0 {
  strings:
    $key_51a0 = { 02 cf [2] 26 c1 [2] 0d ed [2] 23 cf [2] 37 d4 [2] 38 ce [2] 26 d3 [2] 24 d2 [2] 3f d4 [2] 23 d3 [2] 3f fc }

  condition:
    any of them
}