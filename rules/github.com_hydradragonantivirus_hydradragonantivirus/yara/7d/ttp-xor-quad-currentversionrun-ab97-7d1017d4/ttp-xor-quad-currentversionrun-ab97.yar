rule TTP_XOR_QUAD_CurrentVersionRun_ab97 {
  strings:
    $key_ab97 = { f8 f8 [2] dc f6 [2] f7 da [2] d9 f8 [2] cd e3 [2] c2 f9 [2] dc e4 [2] de e5 [2] c5 e3 [2] d9 e4 [2] c5 cb }

  condition:
    any of them
}