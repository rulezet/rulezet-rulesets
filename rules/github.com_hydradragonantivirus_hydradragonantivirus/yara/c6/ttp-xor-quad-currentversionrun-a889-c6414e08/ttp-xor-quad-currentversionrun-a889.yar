rule TTP_XOR_QUAD_CurrentVersionRun_a889 {
  strings:
    $key_a889 = { fb e6 [2] df e8 [2] f4 c4 [2] da e6 [2] ce fd [2] c1 e7 [2] df fa [2] dd fb [2] c6 fd [2] da fa [2] c6 d5 }

  condition:
    any of them
}