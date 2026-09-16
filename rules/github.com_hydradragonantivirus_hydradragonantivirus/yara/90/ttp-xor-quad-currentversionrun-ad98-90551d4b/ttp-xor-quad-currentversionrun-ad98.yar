rule TTP_XOR_QUAD_CurrentVersionRun_ad98 {
  strings:
    $key_ad98 = { fe f7 [2] da f9 [2] f1 d5 [2] df f7 [2] cb ec [2] c4 f6 [2] da eb [2] d8 ea [2] c3 ec [2] df eb [2] c3 c4 }

  condition:
    any of them
}