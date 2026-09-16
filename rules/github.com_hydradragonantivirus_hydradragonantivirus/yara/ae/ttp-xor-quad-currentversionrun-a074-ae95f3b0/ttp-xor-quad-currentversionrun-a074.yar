rule TTP_XOR_QUAD_CurrentVersionRun_a074 {
  strings:
    $key_a074 = { f3 1b [2] d7 15 [2] fc 39 [2] d2 1b [2] c6 00 [2] c9 1a [2] d7 07 [2] d5 06 [2] ce 00 [2] d2 07 [2] ce 28 }

  condition:
    any of them
}