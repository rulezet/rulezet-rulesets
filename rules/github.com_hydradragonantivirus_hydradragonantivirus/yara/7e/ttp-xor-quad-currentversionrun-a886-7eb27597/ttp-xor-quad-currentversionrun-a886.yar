rule TTP_XOR_QUAD_CurrentVersionRun_a886 {
  strings:
    $key_a886 = { fb e9 [2] df e7 [2] f4 cb [2] da e9 [2] ce f2 [2] c1 e8 [2] df f5 [2] dd f4 [2] c6 f2 [2] da f5 [2] c6 da }

  condition:
    any of them
}