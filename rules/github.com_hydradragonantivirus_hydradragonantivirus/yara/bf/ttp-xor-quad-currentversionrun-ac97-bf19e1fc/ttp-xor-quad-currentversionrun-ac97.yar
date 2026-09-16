rule TTP_XOR_QUAD_CurrentVersionRun_ac97 {
  strings:
    $key_ac97 = { ff f8 [2] db f6 [2] f0 da [2] de f8 [2] ca e3 [2] c5 f9 [2] db e4 [2] d9 e5 [2] c2 e3 [2] de e4 [2] c2 cb }

  condition:
    any of them
}