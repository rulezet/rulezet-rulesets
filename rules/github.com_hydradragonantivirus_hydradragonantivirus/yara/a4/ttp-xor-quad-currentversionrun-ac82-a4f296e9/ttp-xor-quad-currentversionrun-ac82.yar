rule TTP_XOR_QUAD_CurrentVersionRun_ac82 {
  strings:
    $key_ac82 = { ff ed [2] db e3 [2] f0 cf [2] de ed [2] ca f6 [2] c5 ec [2] db f1 [2] d9 f0 [2] c2 f6 [2] de f1 [2] c2 de }

  condition:
    any of them
}