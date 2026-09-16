rule TTP_XOR_QUAD_CurrentVersionRun_6675 {
  strings:
    $key_6675 = { 35 1a [2] 11 14 [2] 3a 38 [2] 14 1a [2] 00 01 [2] 0f 1b [2] 11 06 [2] 13 07 [2] 08 01 [2] 14 06 [2] 08 29 }

  condition:
    any of them
}