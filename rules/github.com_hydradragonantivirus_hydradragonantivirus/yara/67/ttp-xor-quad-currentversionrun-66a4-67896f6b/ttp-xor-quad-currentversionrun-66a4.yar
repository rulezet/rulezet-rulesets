rule TTP_XOR_QUAD_CurrentVersionRun_66a4 {
  strings:
    $key_66a4 = { 35 cb [2] 11 c5 [2] 3a e9 [2] 14 cb [2] 00 d0 [2] 0f ca [2] 11 d7 [2] 13 d6 [2] 08 d0 [2] 14 d7 [2] 08 f8 }

  condition:
    any of them
}