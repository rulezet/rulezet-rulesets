rule TTP_XOR_QUAD_CurrentVersionRun_bb9e {
  strings:
    $key_bb9e = { e8 f1 [2] cc ff [2] e7 d3 [2] c9 f1 [2] dd ea [2] d2 f0 [2] cc ed [2] ce ec [2] d5 ea [2] c9 ed [2] d5 c2 }

  condition:
    any of them
}