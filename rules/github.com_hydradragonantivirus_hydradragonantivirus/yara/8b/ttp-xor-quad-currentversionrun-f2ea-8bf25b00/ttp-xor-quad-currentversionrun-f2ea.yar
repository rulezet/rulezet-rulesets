rule TTP_XOR_QUAD_CurrentVersionRun_f2ea {
  strings:
    $key_f2ea = { a1 85 [2] 85 8b [2] ae a7 [2] 80 85 [2] 94 9e [2] 9b 84 [2] 85 99 [2] 87 98 [2] 9c 9e [2] 80 99 [2] 9c b6 }

  condition:
    any of them
}