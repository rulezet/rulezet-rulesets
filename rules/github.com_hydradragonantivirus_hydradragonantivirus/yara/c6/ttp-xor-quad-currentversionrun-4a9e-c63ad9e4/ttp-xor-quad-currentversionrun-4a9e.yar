rule TTP_XOR_QUAD_CurrentVersionRun_4a9e {
  strings:
    $key_4a9e = { 19 f1 [2] 3d ff [2] 16 d3 [2] 38 f1 [2] 2c ea [2] 23 f0 [2] 3d ed [2] 3f ec [2] 24 ea [2] 38 ed [2] 24 c2 }

  condition:
    any of them
}