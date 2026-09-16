rule TTP_XOR_QUAD_CurrentVersionRun_a386 {
  strings:
    $key_a386 = { f0 e9 [2] d4 e7 [2] ff cb [2] d1 e9 [2] c5 f2 [2] ca e8 [2] d4 f5 [2] d6 f4 [2] cd f2 [2] d1 f5 [2] cd da }

  condition:
    any of them
}