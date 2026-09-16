rule TTP_XOR_QUAD_CurrentVersionRun_b466 {
  strings:
    $key_b466 = { e7 09 [2] c3 07 [2] e8 2b [2] c6 09 [2] d2 12 [2] dd 08 [2] c3 15 [2] c1 14 [2] da 12 [2] c6 15 [2] da 3a }

  condition:
    any of them
}