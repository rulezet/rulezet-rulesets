rule TTP_XOR_QUAD_CurrentVersionRun_ab85 {
  strings:
    $key_ab85 = { f8 ea [2] dc e4 [2] f7 c8 [2] d9 ea [2] cd f1 [2] c2 eb [2] dc f6 [2] de f7 [2] c5 f1 [2] d9 f6 [2] c5 d9 }

  condition:
    any of them
}