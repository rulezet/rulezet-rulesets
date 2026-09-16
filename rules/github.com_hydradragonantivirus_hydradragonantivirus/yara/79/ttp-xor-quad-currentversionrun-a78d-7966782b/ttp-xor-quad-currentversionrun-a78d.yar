rule TTP_XOR_QUAD_CurrentVersionRun_a78d {
  strings:
    $key_a78d = { f4 e2 [2] d0 ec [2] fb c0 [2] d5 e2 [2] c1 f9 [2] ce e3 [2] d0 fe [2] d2 ff [2] c9 f9 [2] d5 fe [2] c9 d1 }

  condition:
    any of them
}