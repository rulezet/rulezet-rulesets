rule TTP_XOR_QUAD_CurrentVersionRun_5eea {
  strings:
    $key_5eea = { 0d 85 [2] 29 8b [2] 02 a7 [2] 2c 85 [2] 38 9e [2] 37 84 [2] 29 99 [2] 2b 98 [2] 30 9e [2] 2c 99 [2] 30 b6 }

  condition:
    any of them
}