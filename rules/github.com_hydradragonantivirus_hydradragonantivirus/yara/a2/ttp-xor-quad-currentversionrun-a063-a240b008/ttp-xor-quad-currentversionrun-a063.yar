rule TTP_XOR_QUAD_CurrentVersionRun_a063 {
  strings:
    $key_a063 = { f3 0c [2] d7 02 [2] fc 2e [2] d2 0c [2] c6 17 [2] c9 0d [2] d7 10 [2] d5 11 [2] ce 17 [2] d2 10 [2] ce 3f }

  condition:
    any of them
}