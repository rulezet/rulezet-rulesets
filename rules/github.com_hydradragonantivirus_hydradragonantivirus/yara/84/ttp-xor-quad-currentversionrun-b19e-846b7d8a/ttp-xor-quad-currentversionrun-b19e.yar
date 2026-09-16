rule TTP_XOR_QUAD_CurrentVersionRun_b19e {
  strings:
    $key_b19e = { e2 f1 [2] c6 ff [2] ed d3 [2] c3 f1 [2] d7 ea [2] d8 f0 [2] c6 ed [2] c4 ec [2] df ea [2] c3 ed [2] df c2 }

  condition:
    any of them
}