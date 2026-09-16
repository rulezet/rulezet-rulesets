rule TTP_XOR_QUAD_CurrentVersionRun_2575 {
  strings:
    $key_2575 = { 76 1a [2] 52 14 [2] 79 38 [2] 57 1a [2] 43 01 [2] 4c 1b [2] 52 06 [2] 50 07 [2] 4b 01 [2] 57 06 [2] 4b 29 }

  condition:
    any of them
}