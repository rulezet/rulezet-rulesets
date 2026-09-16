rule TTP_XOR_QUAD_CurrentVersionRun_ac83 {
  strings:
    $key_ac83 = { ff ec [2] db e2 [2] f0 ce [2] de ec [2] ca f7 [2] c5 ed [2] db f0 [2] d9 f1 [2] c2 f7 [2] de f0 [2] c2 df }

  condition:
    any of them
}