rule TTP_XOR_QUAD_CurrentVersionRun_a079 {
  strings:
    $key_a079 = { f3 16 [2] d7 18 [2] fc 34 [2] d2 16 [2] c6 0d [2] c9 17 [2] d7 0a [2] d5 0b [2] ce 0d [2] d2 0a [2] ce 25 }

  condition:
    any of them
}