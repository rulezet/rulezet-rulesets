rule TTP_XOR_QUAD_CurrentVersionRun_ac9e {
  strings:
    $key_ac9e = { ff f1 [2] db ff [2] f0 d3 [2] de f1 [2] ca ea [2] c5 f0 [2] db ed [2] d9 ec [2] c2 ea [2] de ed [2] c2 c2 }

  condition:
    any of them
}