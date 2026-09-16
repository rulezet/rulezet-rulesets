rule TTP_XOR_QUAD_CurrentVersionRun_a097 {
  strings:
    $key_a097 = { f3 f8 [2] d7 f6 [2] fc da [2] d2 f8 [2] c6 e3 [2] c9 f9 [2] d7 e4 [2] d5 e5 [2] ce e3 [2] d2 e4 [2] ce cb }

  condition:
    any of them
}