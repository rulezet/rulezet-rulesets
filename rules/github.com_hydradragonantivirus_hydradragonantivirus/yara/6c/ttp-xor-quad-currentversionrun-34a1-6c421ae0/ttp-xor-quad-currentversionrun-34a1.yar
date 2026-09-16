rule TTP_XOR_QUAD_CurrentVersionRun_34a1 {
  strings:
    $key_34a1 = { 67 ce [2] 43 c0 [2] 68 ec [2] 46 ce [2] 52 d5 [2] 5d cf [2] 43 d2 [2] 41 d3 [2] 5a d5 [2] 46 d2 [2] 5a fd }

  condition:
    any of them
}