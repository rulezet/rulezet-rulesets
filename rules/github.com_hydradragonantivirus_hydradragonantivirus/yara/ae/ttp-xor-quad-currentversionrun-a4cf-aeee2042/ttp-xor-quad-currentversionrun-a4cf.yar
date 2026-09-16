rule TTP_XOR_QUAD_CurrentVersionRun_a4cf {
  strings:
    $key_a4cf = { f7 a0 [2] d3 ae [2] f8 82 [2] d6 a0 [2] c2 bb [2] cd a1 [2] d3 bc [2] d1 bd [2] ca bb [2] d6 bc [2] ca 93 }

  condition:
    any of them
}