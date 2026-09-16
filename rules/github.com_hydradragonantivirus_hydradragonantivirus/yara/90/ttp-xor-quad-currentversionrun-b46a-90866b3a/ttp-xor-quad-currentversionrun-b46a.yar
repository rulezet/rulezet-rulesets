rule TTP_XOR_QUAD_CurrentVersionRun_b46a {
  strings:
    $key_b46a = { e7 05 [2] c3 0b [2] e8 27 [2] c6 05 [2] d2 1e [2] dd 04 [2] c3 19 [2] c1 18 [2] da 1e [2] c6 19 [2] da 36 }

  condition:
    any of them
}