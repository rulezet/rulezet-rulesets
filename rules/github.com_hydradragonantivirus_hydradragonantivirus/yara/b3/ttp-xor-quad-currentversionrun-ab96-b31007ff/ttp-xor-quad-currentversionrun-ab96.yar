rule TTP_XOR_QUAD_CurrentVersionRun_ab96 {
  strings:
    $key_ab96 = { f8 f9 [2] dc f7 [2] f7 db [2] d9 f9 [2] cd e2 [2] c2 f8 [2] dc e5 [2] de e4 [2] c5 e2 [2] d9 e5 [2] c5 ca }

  condition:
    any of them
}