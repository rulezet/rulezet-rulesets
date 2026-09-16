rule TTP_XOR_QUAD_CurrentVersionRun_6678 {
  strings:
    $key_6678 = { 35 17 [2] 11 19 [2] 3a 35 [2] 14 17 [2] 00 0c [2] 0f 16 [2] 11 0b [2] 13 0a [2] 08 0c [2] 14 0b [2] 08 24 }

  condition:
    any of them
}