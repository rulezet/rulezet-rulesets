rule TTP_XOR_QUAD_CurrentVersionRun_ab94 {
  strings:
    $key_ab94 = { f8 fb [2] dc f5 [2] f7 d9 [2] d9 fb [2] cd e0 [2] c2 fa [2] dc e7 [2] de e6 [2] c5 e0 [2] d9 e7 [2] c5 c8 }

  condition:
    any of them
}