rule TTP_XOR_QUAD_CurrentVersionRun_6e9e {
  strings:
    $key_6e9e = { 3d f1 [2] 19 ff [2] 32 d3 [2] 1c f1 [2] 08 ea [2] 07 f0 [2] 19 ed [2] 1b ec [2] 00 ea [2] 1c ed [2] 00 c2 }

  condition:
    any of them
}