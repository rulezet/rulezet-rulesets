rule TTP_XOR_QUAD_CurrentVersionRun_b08c {
  strings:
    $key_b08c = { e3 e3 [2] c7 ed [2] ec c1 [2] c2 e3 [2] d6 f8 [2] d9 e2 [2] c7 ff [2] c5 fe [2] de f8 [2] c2 ff [2] de d0 }

  condition:
    any of them
}