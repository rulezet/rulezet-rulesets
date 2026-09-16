rule TTP_XOR_QUAD_CurrentVersionRun_42ea {
  strings:
    $key_42ea = { 11 85 [2] 35 8b [2] 1e a7 [2] 30 85 [2] 24 9e [2] 2b 84 [2] 35 99 [2] 37 98 [2] 2c 9e [2] 30 99 [2] 2c b6 }

  condition:
    any of them
}