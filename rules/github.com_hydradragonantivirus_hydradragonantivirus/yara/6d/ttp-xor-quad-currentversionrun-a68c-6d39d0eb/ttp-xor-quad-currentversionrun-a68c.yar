rule TTP_XOR_QUAD_CurrentVersionRun_a68c {
  strings:
    $key_a68c = { f5 e3 [2] d1 ed [2] fa c1 [2] d4 e3 [2] c0 f8 [2] cf e2 [2] d1 ff [2] d3 fe [2] c8 f8 [2] d4 ff [2] c8 d0 }

  condition:
    any of them
}