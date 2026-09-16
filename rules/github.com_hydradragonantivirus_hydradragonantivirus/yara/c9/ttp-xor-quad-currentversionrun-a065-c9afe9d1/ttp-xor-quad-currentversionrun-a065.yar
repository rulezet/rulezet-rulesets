rule TTP_XOR_QUAD_CurrentVersionRun_a065 {
  strings:
    $key_a065 = { f3 0a [2] d7 04 [2] fc 28 [2] d2 0a [2] c6 11 [2] c9 0b [2] d7 16 [2] d5 17 [2] ce 11 [2] d2 16 [2] ce 39 }

  condition:
    any of them
}