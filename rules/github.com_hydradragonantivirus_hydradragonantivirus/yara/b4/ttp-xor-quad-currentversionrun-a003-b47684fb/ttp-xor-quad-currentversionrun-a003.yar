rule TTP_XOR_QUAD_CurrentVersionRun_a003 {
  strings:
    $key_a003 = { f3 6c [2] d7 62 [2] fc 4e [2] d2 6c [2] c6 77 [2] c9 6d [2] d7 70 [2] d5 71 [2] ce 77 [2] d2 70 [2] ce 5f }

  condition:
    any of them
}