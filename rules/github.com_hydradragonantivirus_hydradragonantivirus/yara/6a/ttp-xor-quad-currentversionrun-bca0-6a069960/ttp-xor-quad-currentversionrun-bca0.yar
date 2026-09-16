rule TTP_XOR_QUAD_CurrentVersionRun_bca0 {
  strings:
    $key_bca0 = { ef cf [2] cb c1 [2] e0 ed [2] ce cf [2] da d4 [2] d5 ce [2] cb d3 [2] c9 d2 [2] d2 d4 [2] ce d3 [2] d2 fc }

  condition:
    any of them
}