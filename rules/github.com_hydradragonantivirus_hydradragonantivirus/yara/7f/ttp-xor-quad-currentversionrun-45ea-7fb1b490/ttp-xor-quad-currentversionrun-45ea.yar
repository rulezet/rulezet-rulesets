rule TTP_XOR_QUAD_CurrentVersionRun_45ea {
  strings:
    $key_45ea = { 16 85 [2] 32 8b [2] 19 a7 [2] 37 85 [2] 23 9e [2] 2c 84 [2] 32 99 [2] 30 98 [2] 2b 9e [2] 37 99 [2] 2b b6 }

  condition:
    any of them
}