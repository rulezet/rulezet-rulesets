rule TTP_XOR_QUAD_CurrentVersionRun_ad9e {
  strings:
    $key_ad9e = { fe f1 [2] da ff [2] f1 d3 [2] df f1 [2] cb ea [2] c4 f0 [2] da ed [2] d8 ec [2] c3 ea [2] df ed [2] c3 c2 }

  condition:
    any of them
}