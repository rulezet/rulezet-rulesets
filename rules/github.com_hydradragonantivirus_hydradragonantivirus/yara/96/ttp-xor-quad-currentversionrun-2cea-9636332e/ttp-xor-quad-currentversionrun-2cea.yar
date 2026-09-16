rule TTP_XOR_QUAD_CurrentVersionRun_2cea {
  strings:
    $key_2cea = { 7f 85 [2] 5b 8b [2] 70 a7 [2] 5e 85 [2] 4a 9e [2] 45 84 [2] 5b 99 [2] 59 98 [2] 42 9e [2] 5e 99 [2] 42 b6 }

  condition:
    any of them
}