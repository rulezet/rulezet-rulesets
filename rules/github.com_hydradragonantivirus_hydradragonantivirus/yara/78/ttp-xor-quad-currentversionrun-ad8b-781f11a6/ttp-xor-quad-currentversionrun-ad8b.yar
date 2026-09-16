rule TTP_XOR_QUAD_CurrentVersionRun_ad8b {
  strings:
    $key_ad8b = { fe e4 [2] da ea [2] f1 c6 [2] df e4 [2] cb ff [2] c4 e5 [2] da f8 [2] d8 f9 [2] c3 ff [2] df f8 [2] c3 d7 }

  condition:
    any of them
}