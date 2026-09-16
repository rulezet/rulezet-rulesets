rule TTP_XOR_QUAD_CurrentVersionRun_14a1 {
  strings:
    $key_14a1 = { 47 ce [2] 63 c0 [2] 48 ec [2] 66 ce [2] 72 d5 [2] 7d cf [2] 63 d2 [2] 61 d3 [2] 7a d5 [2] 66 d2 [2] 7a fd }

  condition:
    any of them
}