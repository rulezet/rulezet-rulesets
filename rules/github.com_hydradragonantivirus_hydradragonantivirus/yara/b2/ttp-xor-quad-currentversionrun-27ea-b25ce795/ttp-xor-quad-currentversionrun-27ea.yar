rule TTP_XOR_QUAD_CurrentVersionRun_27ea {
  strings:
    $key_27ea = { 74 85 [2] 50 8b [2] 7b a7 [2] 55 85 [2] 41 9e [2] 4e 84 [2] 50 99 [2] 52 98 [2] 49 9e [2] 55 99 [2] 49 b6 }

  condition:
    any of them
}