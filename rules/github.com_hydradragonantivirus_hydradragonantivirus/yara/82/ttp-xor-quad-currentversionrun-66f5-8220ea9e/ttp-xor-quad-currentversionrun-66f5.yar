rule TTP_XOR_QUAD_CurrentVersionRun_66f5 {
  strings:
    $key_66f5 = { 35 9a [2] 11 94 [2] 3a b8 [2] 14 9a [2] 00 81 [2] 0f 9b [2] 11 86 [2] 13 87 [2] 08 81 [2] 14 86 [2] 08 a9 }

  condition:
    any of them
}