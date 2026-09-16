rule TTP_XOR_QUAD_CurrentVersionRun_b6ea {
  strings:
    $key_b6ea = { e5 85 [2] c1 8b [2] ea a7 [2] c4 85 [2] d0 9e [2] df 84 [2] c1 99 [2] c3 98 [2] d8 9e [2] c4 99 [2] d8 b6 }

  condition:
    any of them
}