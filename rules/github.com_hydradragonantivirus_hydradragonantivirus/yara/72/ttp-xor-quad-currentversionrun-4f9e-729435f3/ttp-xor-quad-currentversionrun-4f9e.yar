rule TTP_XOR_QUAD_CurrentVersionRun_4f9e {
  strings:
    $key_4f9e = { 1c f1 [2] 38 ff [2] 13 d3 [2] 3d f1 [2] 29 ea [2] 26 f0 [2] 38 ed [2] 3a ec [2] 21 ea [2] 3d ed [2] 21 c2 }

  condition:
    any of them
}