rule TTP_XOR_QUAD_CurrentVersionRun_b09e {
  strings:
    $key_b09e = { e3 f1 [2] c7 ff [2] ec d3 [2] c2 f1 [2] d6 ea [2] d9 f0 [2] c7 ed [2] c5 ec [2] de ea [2] c2 ed [2] de c2 }

  condition:
    any of them
}