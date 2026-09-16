rule TTP_XOR_QUAD_CurrentVersionRun_6679 {
  strings:
    $key_6679 = { 35 16 [2] 11 18 [2] 3a 34 [2] 14 16 [2] 00 0d [2] 0f 17 [2] 11 0a [2] 13 0b [2] 08 0d [2] 14 0a [2] 08 25 }

  condition:
    any of them
}