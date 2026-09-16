rule TTP_XOR_QUAD_CurrentVersionRun_66e9 {
  strings:
    $key_66e9 = { 35 86 [2] 11 88 [2] 3a a4 [2] 14 86 [2] 00 9d [2] 0f 87 [2] 11 9a [2] 13 9b [2] 08 9d [2] 14 9a [2] 08 b5 }

  condition:
    any of them
}