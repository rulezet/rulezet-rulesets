rule TTP_XOR_QUAD_CurrentVersionRun_5e9e {
  strings:
    $key_5e9e = { 0d f1 [2] 29 ff [2] 02 d3 [2] 2c f1 [2] 38 ea [2] 37 f0 [2] 29 ed [2] 2b ec [2] 30 ea [2] 2c ed [2] 30 c2 }

  condition:
    any of them
}