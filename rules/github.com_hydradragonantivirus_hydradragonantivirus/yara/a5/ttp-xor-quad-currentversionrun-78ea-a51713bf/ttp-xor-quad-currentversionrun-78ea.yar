rule TTP_XOR_QUAD_CurrentVersionRun_78ea {
  strings:
    $key_78ea = { 2b 85 [2] 0f 8b [2] 24 a7 [2] 0a 85 [2] 1e 9e [2] 11 84 [2] 0f 99 [2] 0d 98 [2] 16 9e [2] 0a 99 [2] 16 b6 }

  condition:
    any of them
}