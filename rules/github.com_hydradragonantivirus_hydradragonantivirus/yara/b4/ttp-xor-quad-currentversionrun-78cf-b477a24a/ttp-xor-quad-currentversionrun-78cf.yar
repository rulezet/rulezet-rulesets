rule TTP_XOR_QUAD_CurrentVersionRun_78cf {
  strings:
    $key_78cf = { 2b a0 [2] 0f ae [2] 24 82 [2] 0a a0 [2] 1e bb [2] 11 a1 [2] 0f bc [2] 0d bd [2] 16 bb [2] 0a bc [2] 16 93 }

  condition:
    any of them
}