rule TTP_XOR_QUAD_CurrentVersionRun_bad3 {
  strings:
    $key_bad3 = { e9 bc [2] cd b2 [2] e6 9e [2] c8 bc [2] dc a7 [2] d3 bd [2] cd a0 [2] cf a1 [2] d4 a7 [2] c8 a0 [2] d4 8f }

  condition:
    any of them
}