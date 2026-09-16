rule TTP_XOR_QUAD_CurrentVersionRun_72ea {
  strings:
    $key_72ea = { 21 85 [2] 05 8b [2] 2e a7 [2] 00 85 [2] 14 9e [2] 1b 84 [2] 05 99 [2] 07 98 [2] 1c 9e [2] 00 99 [2] 1c b6 }

  condition:
    any of them
}