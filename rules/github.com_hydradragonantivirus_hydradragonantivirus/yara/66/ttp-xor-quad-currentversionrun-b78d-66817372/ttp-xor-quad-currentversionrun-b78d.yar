rule TTP_XOR_QUAD_CurrentVersionRun_b78d {
  strings:
    $key_b78d = { e4 e2 [2] c0 ec [2] eb c0 [2] c5 e2 [2] d1 f9 [2] de e3 [2] c0 fe [2] c2 ff [2] d9 f9 [2] c5 fe [2] d9 d1 }

  condition:
    any of them
}