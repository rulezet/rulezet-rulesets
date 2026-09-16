rule TTP_XOR_QUAD_CurrentVersionRun_5a9e {
  strings:
    $key_5a9e = { 09 f1 [2] 2d ff [2] 06 d3 [2] 28 f1 [2] 3c ea [2] 33 f0 [2] 2d ed [2] 2f ec [2] 34 ea [2] 28 ed [2] 34 c2 }

  condition:
    any of them
}