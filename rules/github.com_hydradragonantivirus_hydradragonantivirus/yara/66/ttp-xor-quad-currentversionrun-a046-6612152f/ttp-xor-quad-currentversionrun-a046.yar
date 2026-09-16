rule TTP_XOR_QUAD_CurrentVersionRun_a046 {
  strings:
    $key_a046 = { f3 29 [2] d7 27 [2] fc 0b [2] d2 29 [2] c6 32 [2] c9 28 [2] d7 35 [2] d5 34 [2] ce 32 [2] d2 35 [2] ce 1a }

  condition:
    any of them
}