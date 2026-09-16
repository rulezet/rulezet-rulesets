rule TTP_XOR_QUAD_CurrentVersionRun_ab95 {
  strings:
    $key_ab95 = { f8 fa [2] dc f4 [2] f7 d8 [2] d9 fa [2] cd e1 [2] c2 fb [2] dc e6 [2] de e7 [2] c5 e1 [2] d9 e6 [2] c5 c9 }

  condition:
    any of them
}