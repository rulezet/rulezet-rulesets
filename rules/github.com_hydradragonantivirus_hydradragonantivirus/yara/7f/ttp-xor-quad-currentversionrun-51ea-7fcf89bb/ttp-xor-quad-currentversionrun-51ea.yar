rule TTP_XOR_QUAD_CurrentVersionRun_51ea {
  strings:
    $key_51ea = { 02 85 [2] 26 8b [2] 0d a7 [2] 23 85 [2] 37 9e [2] 38 84 [2] 26 99 [2] 24 98 [2] 3f 9e [2] 23 99 [2] 3f b6 }

  condition:
    any of them
}