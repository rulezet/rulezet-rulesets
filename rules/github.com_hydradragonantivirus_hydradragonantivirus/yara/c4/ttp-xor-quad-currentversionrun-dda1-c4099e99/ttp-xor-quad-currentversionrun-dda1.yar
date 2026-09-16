rule TTP_XOR_QUAD_CurrentVersionRun_dda1 {
  strings:
    $key_dda1 = { 8e ce [2] aa c0 [2] 81 ec [2] af ce [2] bb d5 [2] b4 cf [2] aa d2 [2] a8 d3 [2] b3 d5 [2] af d2 [2] b3 fd }

  condition:
    any of them
}