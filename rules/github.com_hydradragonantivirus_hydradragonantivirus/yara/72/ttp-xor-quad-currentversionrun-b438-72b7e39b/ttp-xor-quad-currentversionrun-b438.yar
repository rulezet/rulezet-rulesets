rule TTP_XOR_QUAD_CurrentVersionRun_b438 {
  strings:
    $key_b438 = { e7 57 [2] c3 59 [2] e8 75 [2] c6 57 [2] d2 4c [2] dd 56 [2] c3 4b [2] c1 4a [2] da 4c [2] c6 4b [2] da 64 }

  condition:
    any of them
}