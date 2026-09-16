rule TTP_XOR_QUAD_CurrentVersionRun_b181 {
  strings:
    $key_b181 = { e2 ee [2] c6 e0 [2] ed cc [2] c3 ee [2] d7 f5 [2] d8 ef [2] c6 f2 [2] c4 f3 [2] df f5 [2] c3 f2 [2] df dd }

  condition:
    any of them
}