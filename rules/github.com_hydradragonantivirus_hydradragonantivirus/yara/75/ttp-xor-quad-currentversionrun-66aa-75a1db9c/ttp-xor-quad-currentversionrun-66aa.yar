rule TTP_XOR_QUAD_CurrentVersionRun_66aa {
  strings:
    $key_66aa = { 35 c5 [2] 11 cb [2] 3a e7 [2] 14 c5 [2] 00 de [2] 0f c4 [2] 11 d9 [2] 13 d8 [2] 08 de [2] 14 d9 [2] 08 f6 }

  condition:
    any of them
}