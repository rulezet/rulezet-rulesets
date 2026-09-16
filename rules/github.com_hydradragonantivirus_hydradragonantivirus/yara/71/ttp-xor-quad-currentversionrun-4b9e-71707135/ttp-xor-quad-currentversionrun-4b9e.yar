rule TTP_XOR_QUAD_CurrentVersionRun_4b9e {
  strings:
    $key_4b9e = { 18 f1 [2] 3c ff [2] 17 d3 [2] 39 f1 [2] 2d ea [2] 22 f0 [2] 3c ed [2] 3e ec [2] 25 ea [2] 39 ed [2] 25 c2 }

  condition:
    any of them
}