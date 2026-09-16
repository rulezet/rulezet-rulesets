rule TTP_XOR_QUAD_CurrentVersionRun_badc {
  strings:
    $key_badc = { e9 b3 [2] cd bd [2] e6 91 [2] c8 b3 [2] dc a8 [2] d3 b2 [2] cd af [2] cf ae [2] d4 a8 [2] c8 af [2] d4 80 }

  condition:
    any of them
}