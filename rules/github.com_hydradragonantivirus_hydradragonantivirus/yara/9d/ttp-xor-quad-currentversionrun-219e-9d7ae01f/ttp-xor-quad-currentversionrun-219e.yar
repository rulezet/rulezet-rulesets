rule TTP_XOR_QUAD_CurrentVersionRun_219e {
  strings:
    $key_219e = { 72 f1 [2] 56 ff [2] 7d d3 [2] 53 f1 [2] 47 ea [2] 48 f0 [2] 56 ed [2] 54 ec [2] 4f ea [2] 53 ed [2] 4f c2 }

  condition:
    any of them
}