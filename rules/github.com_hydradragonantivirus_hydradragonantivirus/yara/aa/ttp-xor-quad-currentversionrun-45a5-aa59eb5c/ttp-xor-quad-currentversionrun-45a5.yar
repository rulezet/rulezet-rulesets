rule TTP_XOR_QUAD_CurrentVersionRun_45a5 {
  strings:
    $key_45a5 = { 16 ca [2] 32 c4 [2] 19 e8 [2] 37 ca [2] 23 d1 [2] 2c cb [2] 32 d6 [2] 30 d7 [2] 2b d1 [2] 37 d6 [2] 2b f9 }

  condition:
    any of them
}