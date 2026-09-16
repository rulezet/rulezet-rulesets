rule TTP_XOR_QUAD_CurrentVersionRun_2f75 {
  strings:
    $key_2f75 = { 7c 1a [2] 58 14 [2] 73 38 [2] 5d 1a [2] 49 01 [2] 46 1b [2] 58 06 [2] 5a 07 [2] 41 01 [2] 5d 06 [2] 41 29 }

  condition:
    any of them
}