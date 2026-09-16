rule TTP_XOR_QUAD_CurrentVersionRun_a069 {
  strings:
    $key_a069 = { f3 06 [2] d7 08 [2] fc 24 [2] d2 06 [2] c6 1d [2] c9 07 [2] d7 1a [2] d5 1b [2] ce 1d [2] d2 1a [2] ce 35 }

  condition:
    any of them
}