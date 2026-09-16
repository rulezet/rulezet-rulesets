rule TTP_XOR_QUAD_CurrentVersionRun_a894 {
  strings:
    $key_a894 = { fb fb [2] df f5 [2] f4 d9 [2] da fb [2] ce e0 [2] c1 fa [2] df e7 [2] dd e6 [2] c6 e0 [2] da e7 [2] c6 c8 }

  condition:
    any of them
}