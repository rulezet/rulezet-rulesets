rule TTP_XOR_QUAD_CurrentVersionRun_31ea {
  strings:
    $key_31ea = { 62 85 [2] 46 8b [2] 6d a7 [2] 43 85 [2] 57 9e [2] 58 84 [2] 46 99 [2] 44 98 [2] 5f 9e [2] 43 99 [2] 5f b6 }

  condition:
    any of them
}