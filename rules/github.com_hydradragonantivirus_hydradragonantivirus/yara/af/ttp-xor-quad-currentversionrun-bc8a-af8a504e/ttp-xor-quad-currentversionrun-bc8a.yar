rule TTP_XOR_QUAD_CurrentVersionRun_bc8a {
  strings:
    $key_bc8a = { ef e5 [2] cb eb [2] e0 c7 [2] ce e5 [2] da fe [2] d5 e4 [2] cb f9 [2] c9 f8 [2] d2 fe [2] ce f9 [2] d2 d6 }

  condition:
    any of them
}