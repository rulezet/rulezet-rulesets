rule TTP_XOR_QUAD_CurrentVersionRun_a077 {
  strings:
    $key_a077 = { f3 18 [2] d7 16 [2] fc 3a [2] d2 18 [2] c6 03 [2] c9 19 [2] d7 04 [2] d5 05 [2] ce 03 [2] d2 04 [2] ce 2b }

  condition:
    any of them
}