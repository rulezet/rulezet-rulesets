rule TTP_XOR_QUAD_CurrentVersionRun_4e9e {
  strings:
    $key_4e9e = { 1d f1 [2] 39 ff [2] 12 d3 [2] 3c f1 [2] 28 ea [2] 27 f0 [2] 39 ed [2] 3b ec [2] 20 ea [2] 3c ed [2] 20 c2 }

  condition:
    any of them
}