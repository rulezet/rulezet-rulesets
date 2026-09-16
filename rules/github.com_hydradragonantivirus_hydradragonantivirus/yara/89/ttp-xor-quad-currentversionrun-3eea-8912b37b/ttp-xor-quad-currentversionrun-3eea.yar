rule TTP_XOR_QUAD_CurrentVersionRun_3eea {
  strings:
    $key_3eea = { 6d 85 [2] 49 8b [2] 62 a7 [2] 4c 85 [2] 58 9e [2] 57 84 [2] 49 99 [2] 4b 98 [2] 50 9e [2] 4c 99 [2] 50 b6 }

  condition:
    any of them
}