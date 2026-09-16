rule TTP_XOR_QUAD_CurrentVersionRun_a985 {
  strings:
    $key_a985 = { fa ea [2] de e4 [2] f5 c8 [2] db ea [2] cf f1 [2] c0 eb [2] de f6 [2] dc f7 [2] c7 f1 [2] db f6 [2] c7 d9 }

  condition:
    any of them
}