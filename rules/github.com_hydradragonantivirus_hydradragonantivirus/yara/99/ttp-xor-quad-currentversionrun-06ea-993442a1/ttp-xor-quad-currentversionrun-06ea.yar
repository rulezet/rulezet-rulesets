rule TTP_XOR_QUAD_CurrentVersionRun_06ea {
  strings:
    $key_06ea = { 55 85 [2] 71 8b [2] 5a a7 [2] 74 85 [2] 60 9e [2] 6f 84 [2] 71 99 [2] 73 98 [2] 68 9e [2] 74 99 [2] 68 b6 }

  condition:
    any of them
}