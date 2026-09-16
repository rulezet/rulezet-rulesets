rule TTP_XOR_QUAD_CurrentVersionRun_ad83 {
  strings:
    $key_ad83 = { fe ec [2] da e2 [2] f1 ce [2] df ec [2] cb f7 [2] c4 ed [2] da f0 [2] d8 f1 [2] c3 f7 [2] df f0 [2] c3 df }

  condition:
    any of them
}