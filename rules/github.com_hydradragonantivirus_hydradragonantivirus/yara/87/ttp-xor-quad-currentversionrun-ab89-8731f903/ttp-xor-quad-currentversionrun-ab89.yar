rule TTP_XOR_QUAD_CurrentVersionRun_ab89 {
  strings:
    $key_ab89 = { f8 e6 [2] dc e8 [2] f7 c4 [2] d9 e6 [2] cd fd [2] c2 e7 [2] dc fa [2] de fb [2] c5 fd [2] d9 fa [2] c5 d5 }

  condition:
    any of them
}