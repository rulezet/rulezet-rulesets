rule TTP_XOR_QUAD_CurrentVersionRun_abcf {
  strings:
    $key_abcf = { f8 a0 [2] dc ae [2] f7 82 [2] d9 a0 [2] cd bb [2] c2 a1 [2] dc bc [2] de bd [2] c5 bb [2] d9 bc [2] c5 93 }

  condition:
    any of them
}