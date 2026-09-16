rule TTP_XOR_QUAD_CurrentVersionRun_36ea {
  strings:
    $key_36ea = { 65 85 [2] 41 8b [2] 6a a7 [2] 44 85 [2] 50 9e [2] 5f 84 [2] 41 99 [2] 43 98 [2] 58 9e [2] 44 99 [2] 58 b6 }

  condition:
    any of them
}