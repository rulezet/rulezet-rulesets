rule TTP_XOR_QUAD_CurrentVersionRun_cf9e {
  strings:
    $key_cf9e = { 9c f1 [2] b8 ff [2] 93 d3 [2] bd f1 [2] a9 ea [2] a6 f0 [2] b8 ed [2] ba ec [2] a1 ea [2] bd ed [2] a1 c2 }

  condition:
    any of them
}