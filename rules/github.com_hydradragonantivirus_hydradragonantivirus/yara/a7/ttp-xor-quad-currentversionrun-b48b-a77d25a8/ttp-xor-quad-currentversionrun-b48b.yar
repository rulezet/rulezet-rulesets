rule TTP_XOR_QUAD_CurrentVersionRun_b48b {
  strings:
    $key_b48b = { e7 e4 [2] c3 ea [2] e8 c6 [2] c6 e4 [2] d2 ff [2] dd e5 [2] c3 f8 [2] c1 f9 [2] da ff [2] c6 f8 [2] da d7 }

  condition:
    any of them
}