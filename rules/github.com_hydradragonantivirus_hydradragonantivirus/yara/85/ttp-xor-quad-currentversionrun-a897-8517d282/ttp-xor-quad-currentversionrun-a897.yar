rule TTP_XOR_QUAD_CurrentVersionRun_a897 {
  strings:
    $key_a897 = { fb f8 [2] df f6 [2] f4 da [2] da f8 [2] ce e3 [2] c1 f9 [2] df e4 [2] dd e5 [2] c6 e3 [2] da e4 [2] c6 cb }

  condition:
    any of them
}