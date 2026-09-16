rule TTP_XOR_QUAD_CurrentVersionRun_aca0 {
  strings:
    $key_aca0 = { ff cf [2] db c1 [2] f0 ed [2] de cf [2] ca d4 [2] c5 ce [2] db d3 [2] d9 d2 [2] c2 d4 [2] de d3 [2] c2 fc }

  condition:
    any of them
}