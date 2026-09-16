rule TTP_XOR_QUAD_CurrentVersionRun_bacf {
  strings:
    $key_bacf = { e9 a0 [2] cd ae [2] e6 82 [2] c8 a0 [2] dc bb [2] d3 a1 [2] cd bc [2] cf bd [2] d4 bb [2] c8 bc [2] d4 93 }

  condition:
    any of them
}