rule TTP_XOR_QUAD_CurrentVersionRun_eea4 {
  strings:
    $key_eea4 = { bd cb [2] 99 c5 [2] b2 e9 [2] 9c cb [2] 88 d0 [2] 87 ca [2] 99 d7 [2] 9b d6 [2] 80 d0 [2] 9c d7 [2] 80 f8 }

  condition:
    any of them
}