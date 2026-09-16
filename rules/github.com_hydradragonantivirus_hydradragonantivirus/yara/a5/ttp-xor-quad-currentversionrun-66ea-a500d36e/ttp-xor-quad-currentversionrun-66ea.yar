rule TTP_XOR_QUAD_CurrentVersionRun_66ea {
  strings:
    $key_66ea = { 35 85 [2] 11 8b [2] 3a a7 [2] 14 85 [2] 00 9e [2] 0f 84 [2] 11 99 [2] 13 98 [2] 08 9e [2] 14 99 [2] 08 b6 }

  condition:
    any of them
}