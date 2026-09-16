rule TTP_XOR_QUAD_CurrentVersionRun_69e9 {
  strings:
    $key_69e9 = { 3a 86 [2] 1e 88 [2] 35 a4 [2] 1b 86 [2] 0f 9d [2] 00 87 [2] 1e 9a [2] 1c 9b [2] 07 9d [2] 1b 9a [2] 07 b5 }

  condition:
    any of them
}