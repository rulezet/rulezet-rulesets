rule TTP_XOR_QUAD_CurrentVersionRun_b8cf {
  strings:
    $key_b8cf = { eb a0 [2] cf ae [2] e4 82 [2] ca a0 [2] de bb [2] d1 a1 [2] cf bc [2] cd bd [2] d6 bb [2] ca bc [2] d6 93 }

  condition:
    any of them
}