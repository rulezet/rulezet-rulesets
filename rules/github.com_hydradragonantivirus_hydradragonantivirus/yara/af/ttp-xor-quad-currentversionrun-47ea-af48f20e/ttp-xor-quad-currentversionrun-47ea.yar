rule TTP_XOR_QUAD_CurrentVersionRun_47ea {
  strings:
    $key_47ea = { 14 85 [2] 30 8b [2] 1b a7 [2] 35 85 [2] 21 9e [2] 2e 84 [2] 30 99 [2] 32 98 [2] 29 9e [2] 35 99 [2] 29 b6 }

  condition:
    any of them
}