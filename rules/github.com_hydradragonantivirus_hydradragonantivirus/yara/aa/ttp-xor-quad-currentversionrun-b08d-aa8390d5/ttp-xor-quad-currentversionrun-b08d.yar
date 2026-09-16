rule TTP_XOR_QUAD_CurrentVersionRun_b08d {
  strings:
    $key_b08d = { e3 e2 [2] c7 ec [2] ec c0 [2] c2 e2 [2] d6 f9 [2] d9 e3 [2] c7 fe [2] c5 ff [2] de f9 [2] c2 fe [2] de d1 }

  condition:
    any of them
}