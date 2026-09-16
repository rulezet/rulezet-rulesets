rule TTP_XOR_QUAD_CurrentVersionRun_75a4 {
  strings:
    $key_75a4 = { 26 cb [2] 02 c5 [2] 29 e9 [2] 07 cb [2] 13 d0 [2] 1c ca [2] 02 d7 [2] 00 d6 [2] 1b d0 [2] 07 d7 [2] 1b f8 }

  condition:
    any of them
}