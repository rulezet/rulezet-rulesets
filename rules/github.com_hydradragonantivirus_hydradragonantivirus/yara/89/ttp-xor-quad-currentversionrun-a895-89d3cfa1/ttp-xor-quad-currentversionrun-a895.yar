rule TTP_XOR_QUAD_CurrentVersionRun_a895 {
  strings:
    $key_a895 = { fb fa [2] df f4 [2] f4 d8 [2] da fa [2] ce e1 [2] c1 fb [2] df e6 [2] dd e7 [2] c6 e1 [2] da e6 [2] c6 c9 }

  condition:
    any of them
}