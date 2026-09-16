rule TTP_XOR_QUAD_CurrentVersionRun_ce9e {
  strings:
    $key_ce9e = { 9d f1 [2] b9 ff [2] 92 d3 [2] bc f1 [2] a8 ea [2] a7 f0 [2] b9 ed [2] bb ec [2] a0 ea [2] bc ed [2] a0 c2 }

  condition:
    any of them
}