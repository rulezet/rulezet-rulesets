rule TTP_XOR_QUAD_CurrentVersionRun_a044 {
  strings:
    $key_a044 = { f3 2b [2] d7 25 [2] fc 09 [2] d2 2b [2] c6 30 [2] c9 2a [2] d7 37 [2] d5 36 [2] ce 30 [2] d2 37 [2] ce 18 }

  condition:
    any of them
}