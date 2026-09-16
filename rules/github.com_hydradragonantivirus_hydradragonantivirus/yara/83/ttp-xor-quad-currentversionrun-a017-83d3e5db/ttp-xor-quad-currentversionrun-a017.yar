rule TTP_XOR_QUAD_CurrentVersionRun_a017 {
  strings:
    $key_a017 = { f3 78 [2] d7 76 [2] fc 5a [2] d2 78 [2] c6 63 [2] c9 79 [2] d7 64 [2] d5 65 [2] ce 63 [2] d2 64 [2] ce 4b }

  condition:
    any of them
}