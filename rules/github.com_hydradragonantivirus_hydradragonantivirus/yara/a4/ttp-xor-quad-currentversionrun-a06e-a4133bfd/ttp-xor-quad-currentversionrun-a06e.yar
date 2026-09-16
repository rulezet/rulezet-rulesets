rule TTP_XOR_QUAD_CurrentVersionRun_a06e {
  strings:
    $key_a06e = { f3 01 [2] d7 0f [2] fc 23 [2] d2 01 [2] c6 1a [2] c9 00 [2] d7 1d [2] d5 1c [2] ce 1a [2] d2 1d [2] ce 32 }

  condition:
    any of them
}