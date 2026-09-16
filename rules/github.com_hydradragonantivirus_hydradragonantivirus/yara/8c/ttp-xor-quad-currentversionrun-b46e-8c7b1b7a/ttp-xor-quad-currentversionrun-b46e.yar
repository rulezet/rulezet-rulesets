rule TTP_XOR_QUAD_CurrentVersionRun_b46e {
  strings:
    $key_b46e = { e7 01 [2] c3 0f [2] e8 23 [2] c6 01 [2] d2 1a [2] dd 00 [2] c3 1d [2] c1 1c [2] da 1a [2] c6 1d [2] da 32 }

  condition:
    any of them
}