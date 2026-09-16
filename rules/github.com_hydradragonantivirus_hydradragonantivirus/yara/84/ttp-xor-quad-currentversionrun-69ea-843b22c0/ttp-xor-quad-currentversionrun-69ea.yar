rule TTP_XOR_QUAD_CurrentVersionRun_69ea {
  strings:
    $key_69ea = { 3a 85 [2] 1e 8b [2] 35 a7 [2] 1b 85 [2] 0f 9e [2] 00 84 [2] 1e 99 [2] 1c 98 [2] 07 9e [2] 1b 99 [2] 07 b6 }

  condition:
    any of them
}