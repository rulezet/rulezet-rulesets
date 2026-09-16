rule TTP_XOR_QUAD_CurrentVersionRun_139e {
  strings:
    $key_139e = { 40 f1 [2] 64 ff [2] 4f d3 [2] 61 f1 [2] 75 ea [2] 7a f0 [2] 64 ed [2] 66 ec [2] 7d ea [2] 61 ed [2] 7d c2 }

  condition:
    any of them
}