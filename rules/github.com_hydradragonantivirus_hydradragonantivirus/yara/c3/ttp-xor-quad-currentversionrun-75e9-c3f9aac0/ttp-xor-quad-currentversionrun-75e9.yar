rule TTP_XOR_QUAD_CurrentVersionRun_75e9 {
  strings:
    $key_75e9 = { 26 86 [2] 02 88 [2] 29 a4 [2] 07 86 [2] 13 9d [2] 1c 87 [2] 02 9a [2] 00 9b [2] 1b 9d [2] 07 9a [2] 1b b5 }

  condition:
    any of them
}