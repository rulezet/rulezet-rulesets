rule TTP_XOR_QUAD_CurrentVersionRun_ad85 {
  strings:
    $key_ad85 = { fe ea [2] da e4 [2] f1 c8 [2] df ea [2] cb f1 [2] c4 eb [2] da f6 [2] d8 f7 [2] c3 f1 [2] df f6 [2] c3 d9 }

  condition:
    any of them
}