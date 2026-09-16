rule TTP_XOR_QUAD_CurrentVersionRun_75b9 {
  strings:
    $key_75b9 = { 26 d6 [2] 02 d8 [2] 29 f4 [2] 07 d6 [2] 13 cd [2] 1c d7 [2] 02 ca [2] 00 cb [2] 1b cd [2] 07 ca [2] 1b e5 }

  condition:
    any of them
}