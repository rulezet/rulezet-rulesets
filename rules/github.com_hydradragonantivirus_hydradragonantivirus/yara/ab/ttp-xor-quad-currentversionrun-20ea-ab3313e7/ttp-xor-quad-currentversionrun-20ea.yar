rule TTP_XOR_QUAD_CurrentVersionRun_20ea {
  strings:
    $key_20ea = { 73 85 [2] 57 8b [2] 7c a7 [2] 52 85 [2] 46 9e [2] 49 84 [2] 57 99 [2] 55 98 [2] 4e 9e [2] 52 99 [2] 4e b6 }

  condition:
    any of them
}