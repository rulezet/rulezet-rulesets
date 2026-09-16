rule TTP_XOR_QUAD_CurrentVersionRun_3cea {
  strings:
    $key_3cea = { 6f 85 [2] 4b 8b [2] 60 a7 [2] 4e 85 [2] 5a 9e [2] 55 84 [2] 4b 99 [2] 49 98 [2] 52 9e [2] 4e 99 [2] 52 b6 }

  condition:
    any of them
}