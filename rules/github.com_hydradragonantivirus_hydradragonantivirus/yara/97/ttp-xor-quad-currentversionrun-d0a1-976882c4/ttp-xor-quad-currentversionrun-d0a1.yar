rule TTP_XOR_QUAD_CurrentVersionRun_d0a1 {
  strings:
    $key_d0a1 = { 83 ce [2] a7 c0 [2] 8c ec [2] a2 ce [2] b6 d5 [2] b9 cf [2] a7 d2 [2] a5 d3 [2] be d5 [2] a2 d2 [2] be fd }

  condition:
    any of them
}