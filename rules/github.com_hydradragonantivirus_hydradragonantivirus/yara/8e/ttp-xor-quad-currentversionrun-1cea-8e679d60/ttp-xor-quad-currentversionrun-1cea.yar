rule TTP_XOR_QUAD_CurrentVersionRun_1cea {
  strings:
    $key_1cea = { 4f 85 [2] 6b 8b [2] 40 a7 [2] 6e 85 [2] 7a 9e [2] 75 84 [2] 6b 99 [2] 69 98 [2] 72 9e [2] 6e 99 [2] 72 b6 }

  condition:
    any of them
}