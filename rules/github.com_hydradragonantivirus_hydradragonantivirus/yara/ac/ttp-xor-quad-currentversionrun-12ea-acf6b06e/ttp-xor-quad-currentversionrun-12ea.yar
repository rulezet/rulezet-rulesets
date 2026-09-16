rule TTP_XOR_QUAD_CurrentVersionRun_12ea {
  strings:
    $key_12ea = { 41 85 [2] 65 8b [2] 4e a7 [2] 60 85 [2] 74 9e [2] 7b 84 [2] 65 99 [2] 67 98 [2] 7c 9e [2] 60 99 [2] 7c b6 }

  condition:
    any of them
}