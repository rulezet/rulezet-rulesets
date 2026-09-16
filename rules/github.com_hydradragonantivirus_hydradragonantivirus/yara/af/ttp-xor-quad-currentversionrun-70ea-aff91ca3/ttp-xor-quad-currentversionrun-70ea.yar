rule TTP_XOR_QUAD_CurrentVersionRun_70ea {
  strings:
    $key_70ea = { 23 85 [2] 07 8b [2] 2c a7 [2] 02 85 [2] 16 9e [2] 19 84 [2] 07 99 [2] 05 98 [2] 1e 9e [2] 02 99 [2] 1e b6 }

  condition:
    any of them
}