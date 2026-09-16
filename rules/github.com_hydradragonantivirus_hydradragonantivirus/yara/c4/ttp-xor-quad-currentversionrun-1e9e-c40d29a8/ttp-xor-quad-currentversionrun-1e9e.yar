rule TTP_XOR_QUAD_CurrentVersionRun_1e9e {
  strings:
    $key_1e9e = { 4d f1 [2] 69 ff [2] 42 d3 [2] 6c f1 [2] 78 ea [2] 77 f0 [2] 69 ed [2] 6b ec [2] 70 ea [2] 6c ed [2] 70 c2 }

  condition:
    any of them
}