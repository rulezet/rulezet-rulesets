rule TTP_XOR_QUAD_CurrentVersionRun_2f9e {
  strings:
    $key_2f9e = { 7c f1 [2] 58 ff [2] 73 d3 [2] 5d f1 [2] 49 ea [2] 46 f0 [2] 58 ed [2] 5a ec [2] 41 ea [2] 5d ed [2] 41 c2 }

  condition:
    any of them
}