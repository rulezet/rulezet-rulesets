rule TTP_XOR_QUAD_CurrentVersionRun_a025 {
  strings:
    $key_a025 = { f3 4a [2] d7 44 [2] fc 68 [2] d2 4a [2] c6 51 [2] c9 4b [2] d7 56 [2] d5 57 [2] ce 51 [2] d2 56 [2] ce 79 }

  condition:
    any of them
}