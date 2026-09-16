rule TTP_XOR_QUAD_CurrentVersionRun_a0d6 {
  strings:
    $key_a0d6 = { f3 b9 [2] d7 b7 [2] fc 9b [2] d2 b9 [2] c6 a2 [2] c9 b8 [2] d7 a5 [2] d5 a4 [2] ce a2 [2] d2 a5 [2] ce 8a }

  condition:
    any of them
}