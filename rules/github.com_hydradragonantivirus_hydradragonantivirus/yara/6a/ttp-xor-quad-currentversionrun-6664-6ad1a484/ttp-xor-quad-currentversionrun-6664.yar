rule TTP_XOR_QUAD_CurrentVersionRun_6664 {
  strings:
    $key_6664 = { 35 0b [2] 11 05 [2] 3a 29 [2] 14 0b [2] 00 10 [2] 0f 0a [2] 11 17 [2] 13 16 [2] 08 10 [2] 14 17 [2] 08 38 }

  condition:
    any of them
}