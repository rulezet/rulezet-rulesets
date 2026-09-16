rule TTP_XOR_QUAD_CurrentVersionRun_7bea {
  strings:
    $key_7bea = { 28 85 [2] 0c 8b [2] 27 a7 [2] 09 85 [2] 1d 9e [2] 12 84 [2] 0c 99 [2] 0e 98 [2] 15 9e [2] 09 99 [2] 15 b6 }

  condition:
    any of them
}