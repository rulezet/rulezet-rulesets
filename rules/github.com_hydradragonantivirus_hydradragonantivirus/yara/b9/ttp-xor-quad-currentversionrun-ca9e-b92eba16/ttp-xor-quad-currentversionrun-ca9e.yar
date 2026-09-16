rule TTP_XOR_QUAD_CurrentVersionRun_ca9e {
  strings:
    $key_ca9e = { 99 f1 [2] bd ff [2] 96 d3 [2] b8 f1 [2] ac ea [2] a3 f0 [2] bd ed [2] bf ec [2] a4 ea [2] b8 ed [2] a4 c2 }

  condition:
    any of them
}