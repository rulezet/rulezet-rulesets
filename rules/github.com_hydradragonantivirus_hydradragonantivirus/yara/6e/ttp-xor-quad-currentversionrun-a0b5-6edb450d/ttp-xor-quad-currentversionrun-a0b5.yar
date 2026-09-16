rule TTP_XOR_QUAD_CurrentVersionRun_a0b5 {
  strings:
    $key_a0b5 = { f3 da [2] d7 d4 [2] fc f8 [2] d2 da [2] c6 c1 [2] c9 db [2] d7 c6 [2] d5 c7 [2] ce c1 [2] d2 c6 [2] ce e9 }

  condition:
    any of them
}