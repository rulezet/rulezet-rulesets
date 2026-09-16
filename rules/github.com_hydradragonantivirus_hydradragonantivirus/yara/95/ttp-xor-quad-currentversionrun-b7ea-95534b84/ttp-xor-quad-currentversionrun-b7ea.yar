rule TTP_XOR_QUAD_CurrentVersionRun_b7ea {
  strings:
    $key_b7ea = { e4 85 [2] c0 8b [2] eb a7 [2] c5 85 [2] d1 9e [2] de 84 [2] c0 99 [2] c2 98 [2] d9 9e [2] c5 99 [2] d9 b6 }

  condition:
    any of them
}