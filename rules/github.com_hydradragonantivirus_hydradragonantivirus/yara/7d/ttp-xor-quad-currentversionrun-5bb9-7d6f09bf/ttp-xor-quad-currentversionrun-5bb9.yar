rule TTP_XOR_QUAD_CurrentVersionRun_5bb9 {
  strings:
    $key_5bb9 = { 08 d6 [2] 2c d8 [2] 07 f4 [2] 29 d6 [2] 3d cd [2] 32 d7 [2] 2c ca [2] 2e cb [2] 35 cd [2] 29 ca [2] 35 e5 }

  condition:
    any of them
}