rule TTP_XOR_QUAD_CurrentVersionRun_ba9e {
  strings:
    $key_ba9e = { e9 f1 [2] cd ff [2] e6 d3 [2] c8 f1 [2] dc ea [2] d3 f0 [2] cd ed [2] cf ec [2] d4 ea [2] c8 ed [2] d4 c2 }

  condition:
    any of them
}