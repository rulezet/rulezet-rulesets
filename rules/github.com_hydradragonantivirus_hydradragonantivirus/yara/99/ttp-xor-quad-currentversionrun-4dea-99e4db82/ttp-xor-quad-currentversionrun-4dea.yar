rule TTP_XOR_QUAD_CurrentVersionRun_4dea {
  strings:
    $key_4dea = { 1e 85 [2] 3a 8b [2] 11 a7 [2] 3f 85 [2] 2b 9e [2] 24 84 [2] 3a 99 [2] 38 98 [2] 23 9e [2] 3f 99 [2] 23 b6 }

  condition:
    any of them
}