rule TTP_XOR_QUAD_CurrentVersionRun_75fa {
  strings:
    $key_75fa = { 26 95 [2] 02 9b [2] 29 b7 [2] 07 95 [2] 13 8e [2] 1c 94 [2] 02 89 [2] 00 88 [2] 1b 8e [2] 07 89 [2] 1b a6 }

  condition:
    any of them
}