rule TTP_XOR_QUAD_CurrentVersionRun_b89e {
  strings:
    $key_b89e = { eb f1 [2] cf ff [2] e4 d3 [2] ca f1 [2] de ea [2] d1 f0 [2] cf ed [2] cd ec [2] d6 ea [2] ca ed [2] d6 c2 }

  condition:
    any of them
}