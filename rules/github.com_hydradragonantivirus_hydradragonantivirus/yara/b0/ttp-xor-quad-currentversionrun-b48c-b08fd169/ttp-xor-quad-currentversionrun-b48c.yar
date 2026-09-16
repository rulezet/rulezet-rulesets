rule TTP_XOR_QUAD_CurrentVersionRun_b48c {
  strings:
    $key_b48c = { e7 e3 [2] c3 ed [2] e8 c1 [2] c6 e3 [2] d2 f8 [2] dd e2 [2] c3 ff [2] c1 fe [2] da f8 [2] c6 ff [2] da d0 }

  condition:
    any of them
}