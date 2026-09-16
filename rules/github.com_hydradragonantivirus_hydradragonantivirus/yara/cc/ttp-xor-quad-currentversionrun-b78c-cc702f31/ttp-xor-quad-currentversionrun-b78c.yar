rule TTP_XOR_QUAD_CurrentVersionRun_b78c {
  strings:
    $key_b78c = { e4 e3 [2] c0 ed [2] eb c1 [2] c5 e3 [2] d1 f8 [2] de e2 [2] c0 ff [2] c2 fe [2] d9 f8 [2] c5 ff [2] d9 d0 }

  condition:
    any of them
}