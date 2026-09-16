rule TTP_XOR_QUAD_CurrentVersionRun_b490 {
  strings:
    $key_b490 = { e7 ff [2] c3 f1 [2] e8 dd [2] c6 ff [2] d2 e4 [2] dd fe [2] c3 e3 [2] c1 e2 [2] da e4 [2] c6 e3 [2] da cc }

  condition:
    any of them
}