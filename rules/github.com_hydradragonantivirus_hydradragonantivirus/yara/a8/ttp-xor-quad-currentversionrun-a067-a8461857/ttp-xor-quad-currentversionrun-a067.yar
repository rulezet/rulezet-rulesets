rule TTP_XOR_QUAD_CurrentVersionRun_a067 {
  strings:
    $key_a067 = { f3 08 [2] d7 06 [2] fc 2a [2] d2 08 [2] c6 13 [2] c9 09 [2] d7 14 [2] d5 15 [2] ce 13 [2] d2 14 [2] ce 3b }

  condition:
    any of them
}