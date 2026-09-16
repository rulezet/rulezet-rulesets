rule TTP_XOR_QUAD_CurrentVersionRun_55ea {
  strings:
    $key_55ea = { 06 85 [2] 22 8b [2] 09 a7 [2] 27 85 [2] 33 9e [2] 3c 84 [2] 22 99 [2] 20 98 [2] 3b 9e [2] 27 99 [2] 3b b6 }

  condition:
    any of them
}