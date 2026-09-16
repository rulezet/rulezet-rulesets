rule TTP_XOR_QUAD_CurrentVersionRun_7b9e {
  strings:
    $key_7b9e = { 28 f1 [2] 0c ff [2] 27 d3 [2] 09 f1 [2] 1d ea [2] 12 f0 [2] 0c ed [2] 0e ec [2] 15 ea [2] 09 ed [2] 15 c2 }

  condition:
    any of them
}