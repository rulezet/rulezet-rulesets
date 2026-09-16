rule TTP_XOR_QUAD_CurrentVersionRun_a054 {
  strings:
    $key_a054 = { f3 3b [2] d7 35 [2] fc 19 [2] d2 3b [2] c6 20 [2] c9 3a [2] d7 27 [2] d5 26 [2] ce 20 [2] d2 27 [2] ce 08 }

  condition:
    any of them
}