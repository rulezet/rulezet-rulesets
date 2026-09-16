rule TTP_XOR_QUAD_CurrentVersionRun_ab9a {
  strings:
    $key_ab9a = { f8 f5 [2] dc fb [2] f7 d7 [2] d9 f5 [2] cd ee [2] c2 f4 [2] dc e9 [2] de e8 [2] c5 ee [2] d9 e9 [2] c5 c6 }

  condition:
    any of them
}