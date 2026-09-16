rule TTP_XOR_QUAD_CurrentVersionRun_b16f {
  strings:
    $key_b16f = { e2 00 [2] c6 0e [2] ed 22 [2] c3 00 [2] d7 1b [2] d8 01 [2] c6 1c [2] c4 1d [2] df 1b [2] c3 1c [2] df 33 }

  condition:
    any of them
}