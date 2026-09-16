rule TTP_XOR_QUAD_CurrentVersionRun_08cf {
  strings:
    $key_08cf = { 5b a0 [2] 7f ae [2] 54 82 [2] 7a a0 [2] 6e bb [2] 61 a1 [2] 7f bc [2] 7d bd [2] 66 bb [2] 7a bc [2] 66 93 }

  condition:
    any of them
}