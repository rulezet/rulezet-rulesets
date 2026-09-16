rule TTP_XOR_QUAD_CurrentVersionRun_a037 {
  strings:
    $key_a037 = { f3 58 [2] d7 56 [2] fc 7a [2] d2 58 [2] c6 43 [2] c9 59 [2] d7 44 [2] d5 45 [2] ce 43 [2] d2 44 [2] ce 6b }

  condition:
    any of them
}