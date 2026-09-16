rule TTP_XOR_QUAD_CurrentVersionRun_2e9e {
  strings:
    $key_2e9e = { 7d f1 [2] 59 ff [2] 72 d3 [2] 5c f1 [2] 48 ea [2] 47 f0 [2] 59 ed [2] 5b ec [2] 40 ea [2] 5c ed [2] 40 c2 }

  condition:
    any of them
}