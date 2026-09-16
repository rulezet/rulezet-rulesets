rule TTP_XOR_QUAD_CurrentVersionRun_6658 {
  strings:
    $key_6658 = { 35 37 [2] 11 39 [2] 3a 15 [2] 14 37 [2] 00 2c [2] 0f 36 [2] 11 2b [2] 13 2a [2] 08 2c [2] 14 2b [2] 08 04 }

  condition:
    any of them
}