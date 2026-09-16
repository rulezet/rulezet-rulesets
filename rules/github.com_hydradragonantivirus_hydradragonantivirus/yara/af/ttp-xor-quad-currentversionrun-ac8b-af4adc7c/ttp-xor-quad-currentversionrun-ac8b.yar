rule TTP_XOR_QUAD_CurrentVersionRun_ac8b {
  strings:
    $key_ac8b = { ff e4 [2] db ea [2] f0 c6 [2] de e4 [2] ca ff [2] c5 e5 [2] db f8 [2] d9 f9 [2] c2 ff [2] de f8 [2] c2 d7 }

  condition:
    any of them
}