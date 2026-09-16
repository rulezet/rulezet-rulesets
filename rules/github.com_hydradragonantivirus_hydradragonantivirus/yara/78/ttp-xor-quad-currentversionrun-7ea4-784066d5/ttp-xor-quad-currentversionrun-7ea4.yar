rule TTP_XOR_QUAD_CurrentVersionRun_7ea4 {
  strings:
    $key_7ea4 = { 2d cb [2] 09 c5 [2] 22 e9 [2] 0c cb [2] 18 d0 [2] 17 ca [2] 09 d7 [2] 0b d6 [2] 10 d0 [2] 0c d7 [2] 10 f8 }

  condition:
    any of them
}