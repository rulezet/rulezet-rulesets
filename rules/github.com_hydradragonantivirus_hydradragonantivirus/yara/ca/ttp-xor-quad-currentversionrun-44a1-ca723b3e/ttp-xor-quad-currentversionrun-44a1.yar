rule TTP_XOR_QUAD_CurrentVersionRun_44a1 {
  strings:
    $key_44a1 = { 17 ce [2] 33 c0 [2] 18 ec [2] 36 ce [2] 22 d5 [2] 2d cf [2] 33 d2 [2] 31 d3 [2] 2a d5 [2] 36 d2 [2] 2a fd }

  condition:
    any of them
}