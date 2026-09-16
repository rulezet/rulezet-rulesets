rule TTP_XOR_QUAD_CurrentVersionRun_48cf {
  strings:
    $key_48cf = { 1b a0 [2] 3f ae [2] 14 82 [2] 3a a0 [2] 2e bb [2] 21 a1 [2] 3f bc [2] 3d bd [2] 26 bb [2] 3a bc [2] 26 93 }

  condition:
    any of them
}