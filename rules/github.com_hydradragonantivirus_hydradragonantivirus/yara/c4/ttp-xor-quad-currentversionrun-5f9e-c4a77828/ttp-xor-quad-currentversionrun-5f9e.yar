rule TTP_XOR_QUAD_CurrentVersionRun_5f9e {
  strings:
    $key_5f9e = { 0c f1 [2] 28 ff [2] 03 d3 [2] 2d f1 [2] 39 ea [2] 36 f0 [2] 28 ed [2] 2a ec [2] 31 ea [2] 2d ed [2] 31 c2 }

  condition:
    any of them
}