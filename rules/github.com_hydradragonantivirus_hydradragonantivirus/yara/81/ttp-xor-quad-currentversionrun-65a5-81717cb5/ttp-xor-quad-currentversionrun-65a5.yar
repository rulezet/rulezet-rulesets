rule TTP_XOR_QUAD_CurrentVersionRun_65a5 {
  strings:
    $key_65a5 = { 36 ca [2] 12 c4 [2] 39 e8 [2] 17 ca [2] 03 d1 [2] 0c cb [2] 12 d6 [2] 10 d7 [2] 0b d1 [2] 17 d6 [2] 0b f9 }

  condition:
    any of them
}