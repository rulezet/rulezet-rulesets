rule TTP_XOR_QUAD_CurrentVersionRun_b48d {
  strings:
    $key_b48d = { e7 e2 [2] c3 ec [2] e8 c0 [2] c6 e2 [2] d2 f9 [2] dd e3 [2] c3 fe [2] c1 ff [2] da f9 [2] c6 fe [2] da d1 }

  condition:
    any of them
}