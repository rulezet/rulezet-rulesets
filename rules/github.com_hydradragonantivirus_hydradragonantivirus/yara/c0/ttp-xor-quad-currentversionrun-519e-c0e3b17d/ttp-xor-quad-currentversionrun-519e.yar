rule TTP_XOR_QUAD_CurrentVersionRun_519e {
  strings:
    $key_519e = { 02 f1 [2] 26 ff [2] 0d d3 [2] 23 f1 [2] 37 ea [2] 38 f0 [2] 26 ed [2] 24 ec [2] 3f ea [2] 23 ed [2] 3f c2 }

  condition:
    any of them
}