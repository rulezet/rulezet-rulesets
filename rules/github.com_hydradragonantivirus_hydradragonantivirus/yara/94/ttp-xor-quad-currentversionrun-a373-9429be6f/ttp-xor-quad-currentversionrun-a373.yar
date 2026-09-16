rule TTP_XOR_QUAD_CurrentVersionRun_a373 {
  strings:
    $key_a373 = { f0 1c [2] d4 12 [2] ff 3e [2] d1 1c [2] c5 07 [2] ca 1d [2] d4 00 [2] d6 01 [2] cd 07 [2] d1 00 [2] cd 2f }

  condition:
    any of them
}