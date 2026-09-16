rule TTP_XOR_QUAD_CurrentVersionRun_75b6 {
  strings:
    $key_75b6 = { 26 d9 [2] 02 d7 [2] 29 fb [2] 07 d9 [2] 13 c2 [2] 1c d8 [2] 02 c5 [2] 00 c4 [2] 1b c2 [2] 07 c5 [2] 1b ea }

  condition:
    any of them
}