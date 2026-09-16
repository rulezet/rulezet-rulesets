rule TTP_XOR_QUAD_CurrentVersionRun_75f4 {
  strings:
    $key_75f4 = { 26 9b [2] 02 95 [2] 29 b9 [2] 07 9b [2] 13 80 [2] 1c 9a [2] 02 87 [2] 00 86 [2] 1b 80 [2] 07 87 [2] 1b a8 }

  condition:
    any of them
}