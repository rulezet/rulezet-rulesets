rule TTP_XOR_QUAD_CurrentVersionRun_b16e {
  strings:
    $key_b16e = { e2 01 [2] c6 0f [2] ed 23 [2] c3 01 [2] d7 1a [2] d8 00 [2] c6 1d [2] c4 1c [2] df 1a [2] c3 1d [2] df 32 }

  condition:
    any of them
}