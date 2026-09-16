rule TTP_XOR_QUAD_CurrentVersionRun_ad94 {
  strings:
    $key_ad94 = { fe fb [2] da f5 [2] f1 d9 [2] df fb [2] cb e0 [2] c4 fa [2] da e7 [2] d8 e6 [2] c3 e0 [2] df e7 [2] c3 c8 }

  condition:
    any of them
}