rule TTP_XOR_QUAD_CurrentVersionRun_b8dc {
  strings:
    $key_b8dc = { eb b3 [2] cf bd [2] e4 91 [2] ca b3 [2] de a8 [2] d1 b2 [2] cf af [2] cd ae [2] d6 a8 [2] ca af [2] d6 80 }

  condition:
    any of them
}