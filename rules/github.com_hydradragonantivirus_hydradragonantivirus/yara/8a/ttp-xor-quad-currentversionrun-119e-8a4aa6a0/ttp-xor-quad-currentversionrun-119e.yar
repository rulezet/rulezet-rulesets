rule TTP_XOR_QUAD_CurrentVersionRun_119e {
  strings:
    $key_119e = { 42 f1 [2] 66 ff [2] 4d d3 [2] 63 f1 [2] 77 ea [2] 78 f0 [2] 66 ed [2] 64 ec [2] 7f ea [2] 63 ed [2] 7f c2 }

  condition:
    any of them
}