rule TTP_XOR_QUAD_CurrentVersionRun_b390 {
  strings:
    $key_b390 = { e0 ff [2] c4 f1 [2] ef dd [2] c1 ff [2] d5 e4 [2] da fe [2] c4 e3 [2] c6 e2 [2] dd e4 [2] c1 e3 [2] dd cc }

  condition:
    any of them
}