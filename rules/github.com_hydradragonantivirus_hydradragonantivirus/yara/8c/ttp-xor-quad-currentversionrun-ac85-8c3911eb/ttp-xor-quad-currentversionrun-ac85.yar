rule TTP_XOR_QUAD_CurrentVersionRun_ac85 {
  strings:
    $key_ac85 = { ff ea [2] db e4 [2] f0 c8 [2] de ea [2] ca f1 [2] c5 eb [2] db f6 [2] d9 f7 [2] c2 f1 [2] de f6 [2] c2 d9 }

  condition:
    any of them
}