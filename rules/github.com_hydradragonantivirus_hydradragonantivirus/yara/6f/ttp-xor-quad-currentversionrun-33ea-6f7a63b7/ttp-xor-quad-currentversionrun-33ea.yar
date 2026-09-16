rule TTP_XOR_QUAD_CurrentVersionRun_33ea {
  strings:
    $key_33ea = { 60 85 [2] 44 8b [2] 6f a7 [2] 41 85 [2] 55 9e [2] 5a 84 [2] 44 99 [2] 46 98 [2] 5d 9e [2] 41 99 [2] 5d b6 }

  condition:
    any of them
}