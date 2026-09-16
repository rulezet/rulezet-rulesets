rule TTP_XOR_QUAD_CurrentVersionRun_b187 {
  strings:
    $key_b187 = { e2 e8 [2] c6 e6 [2] ed ca [2] c3 e8 [2] d7 f3 [2] d8 e9 [2] c6 f4 [2] c4 f5 [2] df f3 [2] c3 f4 [2] df db }

  condition:
    any of them
}