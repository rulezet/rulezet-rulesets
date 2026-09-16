rule TTP_XOR_QUAD_CurrentVersionRun_7dea {
  strings:
    $key_7dea = { 2e 85 [2] 0a 8b [2] 21 a7 [2] 0f 85 [2] 1b 9e [2] 14 84 [2] 0a 99 [2] 08 98 [2] 13 9e [2] 0f 99 [2] 13 b6 }

  condition:
    any of them
}