rule TTP_XOR_QUAD_CurrentVersionRun_a78b {
  strings:
    $key_a78b = { f4 e4 [2] d0 ea [2] fb c6 [2] d5 e4 [2] c1 ff [2] ce e5 [2] d0 f8 [2] d2 f9 [2] c9 ff [2] d5 f8 [2] c9 d7 }

  condition:
    any of them
}