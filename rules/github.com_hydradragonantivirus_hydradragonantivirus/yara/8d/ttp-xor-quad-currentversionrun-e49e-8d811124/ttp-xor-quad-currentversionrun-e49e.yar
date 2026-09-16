rule TTP_XOR_QUAD_CurrentVersionRun_e49e {
  strings:
    $key_e49e = { b7 f1 [2] 93 ff [2] b8 d3 [2] 96 f1 [2] 82 ea [2] 8d f0 [2] 93 ed [2] 91 ec [2] 8a ea [2] 96 ed [2] 8a c2 }

  condition:
    any of them
}