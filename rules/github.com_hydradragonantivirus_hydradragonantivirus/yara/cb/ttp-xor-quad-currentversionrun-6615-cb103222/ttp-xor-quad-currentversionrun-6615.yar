rule TTP_XOR_QUAD_CurrentVersionRun_6615 {
  strings:
    $key_6615 = { 35 7a [2] 11 74 [2] 3a 58 [2] 14 7a [2] 00 61 [2] 0f 7b [2] 11 66 [2] 13 67 [2] 08 61 [2] 14 66 [2] 08 49 }

  condition:
    any of them
}