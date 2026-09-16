rule TTP_XOR_QUAD_CurrentVersionRun_639e {
  strings:
    $key_639e = { 30 f1 [2] 14 ff [2] 3f d3 [2] 11 f1 [2] 05 ea [2] 0a f0 [2] 14 ed [2] 16 ec [2] 0d ea [2] 11 ed [2] 0d c2 }

  condition:
    any of them
}