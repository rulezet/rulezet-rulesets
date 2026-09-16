rule TTP_XOR_QUAD_CurrentVersionRun_6fa4 {
  strings:
    $key_6fa4 = { 3c cb [2] 18 c5 [2] 33 e9 [2] 1d cb [2] 09 d0 [2] 06 ca [2] 18 d7 [2] 1a d6 [2] 01 d0 [2] 1d d7 [2] 01 f8 }

  condition:
    any of them
}