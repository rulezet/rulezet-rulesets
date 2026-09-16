rule TTP_XOR_QUAD_CurrentVersionRun_65a4 {
  strings:
    $key_65a4 = { 36 cb [2] 12 c5 [2] 39 e9 [2] 17 cb [2] 03 d0 [2] 0c ca [2] 12 d7 [2] 10 d6 [2] 0b d0 [2] 17 d7 [2] 0b f8 }

  condition:
    any of them
}