rule TTP_XOR_QUAD_CurrentVersionRun_b43e {
  strings:
    $key_b43e = { e7 51 [2] c3 5f [2] e8 73 [2] c6 51 [2] d2 4a [2] dd 50 [2] c3 4d [2] c1 4c [2] da 4a [2] c6 4d [2] da 62 }

  condition:
    any of them
}