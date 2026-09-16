rule TTP_XOR_QUAD_CurrentVersionRun_ad9a {
  strings:
    $key_ad9a = { fe f5 [2] da fb [2] f1 d7 [2] df f5 [2] cb ee [2] c4 f4 [2] da e9 [2] d8 e8 [2] c3 ee [2] df e9 [2] c3 c6 }

  condition:
    any of them
}