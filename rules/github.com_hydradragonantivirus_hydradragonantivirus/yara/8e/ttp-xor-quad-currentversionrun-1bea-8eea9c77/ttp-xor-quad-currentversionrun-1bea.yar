rule TTP_XOR_QUAD_CurrentVersionRun_1bea {
  strings:
    $key_1bea = { 48 85 [2] 6c 8b [2] 47 a7 [2] 69 85 [2] 7d 9e [2] 72 84 [2] 6c 99 [2] 6e 98 [2] 75 9e [2] 69 99 [2] 75 b6 }

  condition:
    any of them
}