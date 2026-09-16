rule TTP_XOR_QUAD_CurrentVersionRun_f49e {
  strings:
    $key_f49e = { a7 f1 [2] 83 ff [2] a8 d3 [2] 86 f1 [2] 92 ea [2] 9d f0 [2] 83 ed [2] 81 ec [2] 9a ea [2] 86 ed [2] 9a c2 }

  condition:
    any of them
}