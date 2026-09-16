rule TTP_XOR_QUAD_CurrentVersionRun_7eea {
  strings:
    $key_7eea = { 2d 85 [2] 09 8b [2] 22 a7 [2] 0c 85 [2] 18 9e [2] 17 84 [2] 09 99 [2] 0b 98 [2] 10 9e [2] 0c 99 [2] 10 b6 }

  condition:
    any of them
}