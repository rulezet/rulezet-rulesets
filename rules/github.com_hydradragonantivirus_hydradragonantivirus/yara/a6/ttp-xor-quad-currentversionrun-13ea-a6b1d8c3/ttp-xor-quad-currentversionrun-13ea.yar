rule TTP_XOR_QUAD_CurrentVersionRun_13ea {
  strings:
    $key_13ea = { 40 85 [2] 64 8b [2] 4f a7 [2] 61 85 [2] 75 9e [2] 7a 84 [2] 64 99 [2] 66 98 [2] 7d 9e [2] 61 99 [2] 7d b6 }

  condition:
    any of them
}