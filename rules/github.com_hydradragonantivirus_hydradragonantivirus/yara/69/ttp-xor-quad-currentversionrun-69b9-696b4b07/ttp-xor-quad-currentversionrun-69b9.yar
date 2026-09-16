rule TTP_XOR_QUAD_CurrentVersionRun_69b9 {
  strings:
    $key_69b9 = { 3a d6 [2] 1e d8 [2] 35 f4 [2] 1b d6 [2] 0f cd [2] 00 d7 [2] 1e ca [2] 1c cb [2] 07 cd [2] 1b ca [2] 07 e5 }

  condition:
    any of them
}