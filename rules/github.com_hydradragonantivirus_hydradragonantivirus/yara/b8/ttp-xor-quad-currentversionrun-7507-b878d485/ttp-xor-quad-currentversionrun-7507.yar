rule TTP_XOR_QUAD_CurrentVersionRun_7507 {
  strings:
    $key_7507 = { 26 68 [2] 02 66 [2] 29 4a [2] 07 68 [2] 13 73 [2] 1c 69 [2] 02 74 [2] 00 75 [2] 1b 73 [2] 07 74 [2] 1b 5b }

  condition:
    any of them
}