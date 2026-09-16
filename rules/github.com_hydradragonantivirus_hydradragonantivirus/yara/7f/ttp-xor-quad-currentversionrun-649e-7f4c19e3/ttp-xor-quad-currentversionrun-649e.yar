rule TTP_XOR_QUAD_CurrentVersionRun_649e {
  strings:
    $key_649e = { 37 f1 [2] 13 ff [2] 38 d3 [2] 16 f1 [2] 02 ea [2] 0d f0 [2] 13 ed [2] 11 ec [2] 0a ea [2] 16 ed [2] 0a c2 }

  condition:
    any of them
}