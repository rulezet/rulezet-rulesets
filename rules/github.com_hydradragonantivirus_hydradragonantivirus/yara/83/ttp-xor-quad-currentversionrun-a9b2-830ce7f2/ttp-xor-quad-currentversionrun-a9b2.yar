rule TTP_XOR_QUAD_CurrentVersionRun_a9b2 {
  strings:
    $key_a9b2 = { fa dd [2] de d3 [2] f5 ff [2] db dd [2] cf c6 [2] c0 dc [2] de c1 [2] dc c0 [2] c7 c6 [2] db c1 [2] c7 ee }

  condition:
    any of them
}