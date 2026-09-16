rule TTP_XOR_QUAD_CurrentVersionRun_25a4 {
  strings:
    $key_25a4 = { 76 cb [2] 52 c5 [2] 79 e9 [2] 57 cb [2] 43 d0 [2] 4c ca [2] 52 d7 [2] 50 d6 [2] 4b d0 [2] 57 d7 [2] 4b f8 }

  condition:
    any of them
}