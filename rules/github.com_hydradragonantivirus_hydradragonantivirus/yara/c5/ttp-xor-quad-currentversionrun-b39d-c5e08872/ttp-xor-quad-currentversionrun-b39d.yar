rule TTP_XOR_QUAD_CurrentVersionRun_b39d {
  strings:
    $key_b39d = { e0 f2 [2] c4 fc [2] ef d0 [2] c1 f2 [2] d5 e9 [2] da f3 [2] c4 ee [2] c6 ef [2] dd e9 [2] c1 ee [2] dd c1 }

  condition:
    any of them
}