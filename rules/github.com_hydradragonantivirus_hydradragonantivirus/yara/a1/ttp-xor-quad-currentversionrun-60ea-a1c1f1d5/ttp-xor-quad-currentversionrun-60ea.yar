rule TTP_XOR_QUAD_CurrentVersionRun_60ea {
  strings:
    $key_60ea = { 33 85 [2] 17 8b [2] 3c a7 [2] 12 85 [2] 06 9e [2] 09 84 [2] 17 99 [2] 15 98 [2] 0e 9e [2] 12 99 [2] 0e b6 }

  condition:
    any of them
}