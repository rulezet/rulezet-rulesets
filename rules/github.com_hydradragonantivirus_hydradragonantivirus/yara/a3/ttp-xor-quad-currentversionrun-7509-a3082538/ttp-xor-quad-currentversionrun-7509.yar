rule TTP_XOR_QUAD_CurrentVersionRun_7509 {
  strings:
    $key_7509 = { 26 66 [2] 02 68 [2] 29 44 [2] 07 66 [2] 13 7d [2] 1c 67 [2] 02 7a [2] 00 7b [2] 1b 7d [2] 07 7a [2] 1b 55 }

  condition:
    any of them
}