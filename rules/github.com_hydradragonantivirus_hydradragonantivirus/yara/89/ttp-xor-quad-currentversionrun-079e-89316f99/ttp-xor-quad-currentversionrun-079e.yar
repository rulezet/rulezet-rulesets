rule TTP_XOR_QUAD_CurrentVersionRun_079e {
  strings:
    $key_079e = { 54 f1 [2] 70 ff [2] 5b d3 [2] 75 f1 [2] 61 ea [2] 6e f0 [2] 70 ed [2] 72 ec [2] 69 ea [2] 75 ed [2] 69 c2 }

  condition:
    any of them
}