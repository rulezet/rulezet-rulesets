rule TTP_XOR_QUAD_CurrentVersionRun_0b9e {
  strings:
    $key_0b9e = { 58 f1 [2] 7c ff [2] 57 d3 [2] 79 f1 [2] 6d ea [2] 62 f0 [2] 7c ed [2] 7e ec [2] 65 ea [2] 79 ed [2] 65 c2 }

  condition:
    any of them
}