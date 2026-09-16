rule TTP_XOR_QUAD_CurrentVersionRun_6604 {
  strings:
    $key_6604 = { 35 6b [2] 11 65 [2] 3a 49 [2] 14 6b [2] 00 70 [2] 0f 6a [2] 11 77 [2] 13 76 [2] 08 70 [2] 14 77 [2] 08 58 }

  condition:
    any of them
}