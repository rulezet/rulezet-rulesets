rule TTP_XOR_QUAD_CurrentVersionRun_bda0 {
  strings:
    $key_bda0 = { ee cf [2] ca c1 [2] e1 ed [2] cf cf [2] db d4 [2] d4 ce [2] ca d3 [2] c8 d2 [2] d3 d4 [2] cf d3 [2] d3 fc }

  condition:
    any of them
}