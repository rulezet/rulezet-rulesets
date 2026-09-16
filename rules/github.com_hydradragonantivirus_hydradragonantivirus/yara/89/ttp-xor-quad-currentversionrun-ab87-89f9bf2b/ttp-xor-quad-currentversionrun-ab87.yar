rule TTP_XOR_QUAD_CurrentVersionRun_ab87 {
  strings:
    $key_ab87 = { f8 e8 [2] dc e6 [2] f7 ca [2] d9 e8 [2] cd f3 [2] c2 e9 [2] dc f4 [2] de f5 [2] c5 f3 [2] d9 f4 [2] c5 db }

  condition:
    any of them
}