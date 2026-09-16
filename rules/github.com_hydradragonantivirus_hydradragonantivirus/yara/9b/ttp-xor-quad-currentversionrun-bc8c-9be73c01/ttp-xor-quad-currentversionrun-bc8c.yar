rule TTP_XOR_QUAD_CurrentVersionRun_bc8c {
  strings:
    $key_bc8c = { ef e3 [2] cb ed [2] e0 c1 [2] ce e3 [2] da f8 [2] d5 e2 [2] cb ff [2] c9 fe [2] d2 f8 [2] ce ff [2] d2 d0 }

  condition:
    any of them
}