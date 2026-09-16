rule TTP_XOR_QUAD_CurrentVersionRun_a387 {
  strings:
    $key_a387 = { f0 e8 [2] d4 e6 [2] ff ca [2] d1 e8 [2] c5 f3 [2] ca e9 [2] d4 f4 [2] d6 f5 [2] cd f3 [2] d1 f4 [2] cd db }

  condition:
    any of them
}