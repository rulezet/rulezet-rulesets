rule TTP_XOR_QUAD_CurrentVersionRun_45a4 {
  strings:
    $key_45a4 = { 16 cb [2] 32 c5 [2] 19 e9 [2] 37 cb [2] 23 d0 [2] 2c ca [2] 32 d7 [2] 30 d6 [2] 2b d0 [2] 37 d7 [2] 2b f8 }

  condition:
    any of them
}