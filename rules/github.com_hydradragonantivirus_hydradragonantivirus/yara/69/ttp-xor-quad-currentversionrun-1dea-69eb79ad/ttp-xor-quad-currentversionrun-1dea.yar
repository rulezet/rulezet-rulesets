rule TTP_XOR_QUAD_CurrentVersionRun_1dea {
  strings:
    $key_1dea = { 4e 85 [2] 6a 8b [2] 41 a7 [2] 6f 85 [2] 7b 9e [2] 74 84 [2] 6a 99 [2] 68 98 [2] 73 9e [2] 6f 99 [2] 73 b6 }

  condition:
    any of them
}