rule TTP_XOR_QUAD_CurrentVersionRun_5ea4 {
  strings:
    $key_5ea4 = { 0d cb [2] 29 c5 [2] 02 e9 [2] 2c cb [2] 38 d0 [2] 37 ca [2] 29 d7 [2] 2b d6 [2] 30 d0 [2] 2c d7 [2] 30 f8 }

  condition:
    any of them
}