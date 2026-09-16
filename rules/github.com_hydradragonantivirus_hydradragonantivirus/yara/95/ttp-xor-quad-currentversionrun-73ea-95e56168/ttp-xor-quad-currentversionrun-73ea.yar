rule TTP_XOR_QUAD_CurrentVersionRun_73ea {
  strings:
    $key_73ea = { 20 85 [2] 04 8b [2] 2f a7 [2] 01 85 [2] 15 9e [2] 1a 84 [2] 04 99 [2] 06 98 [2] 1d 9e [2] 01 99 [2] 1d b6 }

  condition:
    any of them
}