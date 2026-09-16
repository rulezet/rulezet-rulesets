rule TTP_XOR_QUAD_CurrentVersionRun_eaa1 {
  strings:
    $key_eaa1 = { b9 ce [2] 9d c0 [2] b6 ec [2] 98 ce [2] 8c d5 [2] 83 cf [2] 9d d2 [2] 9f d3 [2] 84 d5 [2] 98 d2 [2] 84 fd }

  condition:
    any of them
}