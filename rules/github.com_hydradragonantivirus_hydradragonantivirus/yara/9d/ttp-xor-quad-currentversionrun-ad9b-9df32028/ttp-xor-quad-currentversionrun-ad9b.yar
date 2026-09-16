rule TTP_XOR_QUAD_CurrentVersionRun_ad9b {
  strings:
    $key_ad9b = { fe f4 [2] da fa [2] f1 d6 [2] df f4 [2] cb ef [2] c4 f5 [2] da e8 [2] d8 e9 [2] c3 ef [2] df e8 [2] c3 c7 }

  condition:
    any of them
}