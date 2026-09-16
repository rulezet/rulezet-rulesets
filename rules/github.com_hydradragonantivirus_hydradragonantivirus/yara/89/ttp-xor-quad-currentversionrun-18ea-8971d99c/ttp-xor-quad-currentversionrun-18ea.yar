rule TTP_XOR_QUAD_CurrentVersionRun_18ea {
  strings:
    $key_18ea = { 4b 85 [2] 6f 8b [2] 44 a7 [2] 6a 85 [2] 7e 9e [2] 71 84 [2] 6f 99 [2] 6d 98 [2] 76 9e [2] 6a 99 [2] 76 b6 }

  condition:
    any of them
}