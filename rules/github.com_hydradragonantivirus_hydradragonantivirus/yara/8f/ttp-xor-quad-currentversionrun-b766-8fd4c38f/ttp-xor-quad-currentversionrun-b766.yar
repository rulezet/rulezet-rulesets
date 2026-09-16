rule TTP_XOR_QUAD_CurrentVersionRun_b766 {
  strings:
    $key_b766 = { e4 09 [2] c0 07 [2] eb 2b [2] c5 09 [2] d1 12 [2] de 08 [2] c0 15 [2] c2 14 [2] d9 12 [2] c5 15 [2] d9 3a }

  condition:
    any of them
}