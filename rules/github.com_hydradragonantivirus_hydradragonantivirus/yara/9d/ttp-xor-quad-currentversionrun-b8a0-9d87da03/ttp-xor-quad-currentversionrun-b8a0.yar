rule TTP_XOR_QUAD_CurrentVersionRun_b8a0 {
  strings:
    $key_b8a0 = { eb cf [2] cf c1 [2] e4 ed [2] ca cf [2] de d4 [2] d1 ce [2] cf d3 [2] cd d2 [2] d6 d4 [2] ca d3 [2] d6 fc }

  condition:
    any of them
}