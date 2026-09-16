rule TTP_XOR_QUAD_CurrentVersionRun_24a1 {
  strings:
    $key_24a1 = { 77 ce [2] 53 c0 [2] 78 ec [2] 56 ce [2] 42 d5 [2] 4d cf [2] 53 d2 [2] 51 d3 [2] 4a d5 [2] 56 d2 [2] 4a fd }

  condition:
    any of them
}