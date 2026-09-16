rule TTP_XOR_QUAD_CurrentVersionRun_0e9e {
  strings:
    $key_0e9e = { 5d f1 [2] 79 ff [2] 52 d3 [2] 7c f1 [2] 68 ea [2] 67 f0 [2] 79 ed [2] 7b ec [2] 60 ea [2] 7c ed [2] 60 c2 }

  condition:
    any of them
}