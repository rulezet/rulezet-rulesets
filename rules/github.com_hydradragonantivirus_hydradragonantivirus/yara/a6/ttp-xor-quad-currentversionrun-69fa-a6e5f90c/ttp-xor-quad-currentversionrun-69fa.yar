rule TTP_XOR_QUAD_CurrentVersionRun_69fa {
  strings:
    $key_69fa = { 3a 95 [2] 1e 9b [2] 35 b7 [2] 1b 95 [2] 0f 8e [2] 00 94 [2] 1e 89 [2] 1c 88 [2] 07 8e [2] 1b 89 [2] 07 a6 }

  condition:
    any of them
}