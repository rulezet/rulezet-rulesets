rule TTP_XOR_QUAD_CurrentVersionRun_76ea {
  strings:
    $key_76ea = { 25 85 [2] 01 8b [2] 2a a7 [2] 04 85 [2] 10 9e [2] 1f 84 [2] 01 99 [2] 03 98 [2] 18 9e [2] 04 99 [2] 18 b6 }

  condition:
    any of them
}