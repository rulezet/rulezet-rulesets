rule TTP_XOR_QUAD_CurrentVersionRun_77ea {
  strings:
    $key_77ea = { 24 85 [2] 00 8b [2] 2b a7 [2] 05 85 [2] 11 9e [2] 1e 84 [2] 00 99 [2] 02 98 [2] 19 9e [2] 05 99 [2] 19 b6 }

  condition:
    any of them
}