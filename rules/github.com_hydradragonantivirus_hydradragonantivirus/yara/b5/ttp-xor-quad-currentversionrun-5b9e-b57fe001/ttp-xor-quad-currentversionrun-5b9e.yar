rule TTP_XOR_QUAD_CurrentVersionRun_5b9e {
  strings:
    $key_5b9e = { 08 f1 [2] 2c ff [2] 07 d3 [2] 29 f1 [2] 3d ea [2] 32 f0 [2] 2c ed [2] 2e ec [2] 35 ea [2] 29 ed [2] 35 c2 }

  condition:
    any of them
}