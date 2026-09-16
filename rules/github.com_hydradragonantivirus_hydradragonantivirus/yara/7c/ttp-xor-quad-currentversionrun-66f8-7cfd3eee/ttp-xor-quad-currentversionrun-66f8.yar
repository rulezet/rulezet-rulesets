rule TTP_XOR_QUAD_CurrentVersionRun_66f8 {
  strings:
    $key_66f8 = { 35 97 [2] 11 99 [2] 3a b5 [2] 14 97 [2] 00 8c [2] 0f 96 [2] 11 8b [2] 13 8a [2] 08 8c [2] 14 8b [2] 08 a4 }

  condition:
    any of them
}