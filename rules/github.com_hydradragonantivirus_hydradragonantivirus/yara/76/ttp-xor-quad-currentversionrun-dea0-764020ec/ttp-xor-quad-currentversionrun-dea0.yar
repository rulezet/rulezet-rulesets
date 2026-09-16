rule TTP_XOR_QUAD_CurrentVersionRun_dea0 {
  strings:
    $key_dea0 = { 8d cf [2] a9 c1 [2] 82 ed [2] ac cf [2] b8 d4 [2] b7 ce [2] a9 d3 [2] ab d2 [2] b0 d4 [2] ac d3 [2] b0 fc }

  condition:
    any of them
}