rule TTP_XOR_QUAD_CurrentVersionRun_75e4 {
  strings:
    $key_75e4 = { 26 8b [2] 02 85 [2] 29 a9 [2] 07 8b [2] 13 90 [2] 1c 8a [2] 02 97 [2] 00 96 [2] 1b 90 [2] 07 97 [2] 1b b8 }

  condition:
    any of them
}