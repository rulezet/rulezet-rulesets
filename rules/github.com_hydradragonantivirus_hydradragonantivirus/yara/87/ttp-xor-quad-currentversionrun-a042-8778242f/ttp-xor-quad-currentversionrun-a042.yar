rule TTP_XOR_QUAD_CurrentVersionRun_a042 {
  strings:
    $key_a042 = { f3 2d [2] d7 23 [2] fc 0f [2] d2 2d [2] c6 36 [2] c9 2c [2] d7 31 [2] d5 30 [2] ce 36 [2] d2 31 [2] ce 1e }

  condition:
    any of them
}