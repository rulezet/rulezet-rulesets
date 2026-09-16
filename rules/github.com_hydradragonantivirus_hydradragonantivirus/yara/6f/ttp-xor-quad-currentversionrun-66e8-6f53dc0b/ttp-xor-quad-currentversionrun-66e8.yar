rule TTP_XOR_QUAD_CurrentVersionRun_66e8 {
  strings:
    $key_66e8 = { 35 87 [2] 11 89 [2] 3a a5 [2] 14 87 [2] 00 9c [2] 0f 86 [2] 11 9b [2] 13 9a [2] 08 9c [2] 14 9b [2] 08 b4 }

  condition:
    any of them
}