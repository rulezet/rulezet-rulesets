rule TTP_XOR_QUAD_CurrentVersionRun_019e {
  strings:
    $key_019e = { 52 f1 [2] 76 ff [2] 5d d3 [2] 73 f1 [2] 67 ea [2] 68 f0 [2] 76 ed [2] 74 ec [2] 6f ea [2] 73 ed [2] 6f c2 }

  condition:
    any of them
}