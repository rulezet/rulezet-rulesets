rule TTP_XOR_QUAD_CurrentVersionRun_75ea {
  strings:
    $key_75ea = { 26 85 [2] 02 8b [2] 29 a7 [2] 07 85 [2] 13 9e [2] 1c 84 [2] 02 99 [2] 00 98 [2] 1b 9e [2] 07 99 [2] 1b b6 }

  condition:
    any of them
}