rule TTP_XOR_QUAD_CurrentVersionRun_719e {
  strings:
    $key_719e = { 22 f1 [2] 06 ff [2] 2d d3 [2] 03 f1 [2] 17 ea [2] 18 f0 [2] 06 ed [2] 04 ec [2] 1f ea [2] 03 ed [2] 1f c2 }

  condition:
    any of them
}