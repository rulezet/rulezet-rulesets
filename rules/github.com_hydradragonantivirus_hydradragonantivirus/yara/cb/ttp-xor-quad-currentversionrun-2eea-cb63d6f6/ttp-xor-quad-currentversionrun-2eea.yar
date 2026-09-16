rule TTP_XOR_QUAD_CurrentVersionRun_2eea {
  strings:
    $key_2eea = { 7d 85 [2] 59 8b [2] 72 a7 [2] 5c 85 [2] 48 9e [2] 47 84 [2] 59 99 [2] 5b 98 [2] 40 9e [2] 5c 99 [2] 40 b6 }

  condition:
    any of them
}