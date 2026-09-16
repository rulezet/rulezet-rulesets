rule TTP_XOR_QUAD_CurrentVersionRun_0bea {
  strings:
    $key_0bea = { 58 85 [2] 7c 8b [2] 57 a7 [2] 79 85 [2] 6d 9e [2] 62 84 [2] 7c 99 [2] 7e 98 [2] 65 9e [2] 79 99 [2] 65 b6 }

  condition:
    any of them
}