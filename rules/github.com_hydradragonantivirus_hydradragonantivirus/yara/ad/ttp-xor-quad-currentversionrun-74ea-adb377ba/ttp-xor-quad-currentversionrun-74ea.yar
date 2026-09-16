rule TTP_XOR_QUAD_CurrentVersionRun_74ea {
  strings:
    $key_74ea = { 27 85 [2] 03 8b [2] 28 a7 [2] 06 85 [2] 12 9e [2] 1d 84 [2] 03 99 [2] 01 98 [2] 1a 9e [2] 06 99 [2] 1a b6 }

  condition:
    any of them
}