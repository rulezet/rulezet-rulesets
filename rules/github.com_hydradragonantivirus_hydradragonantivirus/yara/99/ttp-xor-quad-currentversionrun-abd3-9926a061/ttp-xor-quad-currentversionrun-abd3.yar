rule TTP_XOR_QUAD_CurrentVersionRun_abd3 {
  strings:
    $key_abd3 = { f8 bc [2] dc b2 [2] f7 9e [2] d9 bc [2] cd a7 [2] c2 bd [2] dc a0 [2] de a1 [2] c5 a7 [2] d9 a0 [2] c5 8f }

  condition:
    any of them
}